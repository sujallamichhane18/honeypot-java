import java.io.*;
import java.net.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.*;

public class HoneypotServer {
    private static final Logger LOGGER = Logger.getLogger(HoneypotServer.class.getName());
    private static final String LOG_FILE = "honeypot.log";
    private static final int MAX_ATTEMPTS = 3;
    private static final Map<String, Integer> failedAttempts = new HashMap<>();
    private static final List<LogEntry> logEntries = new ArrayList<>();
    private static final Map<String, Integer> commonUsernames = new HashMap<>();
    private static final Map<String, Integer> commonPasswords = new HashMap<>();
    private static final Map<String, Integer> commonIPs = new HashMap<>();

    static class LogEntry {
        String timestamp;
        String ip;
        String serviceType;
        String details;

        LogEntry(String timestamp, String ip, String serviceType, String details) {
            this.timestamp = timestamp;
            this.ip = ip;
            this.serviceType = serviceType;
            this.details = details;
        }
    }

    public static void main(String[] args) {
        setupLogging();

        new Thread(() -> startServer(22, "SSH")).start();
        new Thread(() -> startServer(80, "HTTP")).start();
        new Thread(() -> startServer(21, "FTP")).start();
        new Thread(() -> startServer(3389, "RDP")).start();
    }

    private static void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler(LOG_FILE, true);
            fileHandler.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.ALL);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }

    private static void startServer(int port, String serviceType) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            LOGGER.info(String.format("%s Honeypot started on port %d", serviceType, port));
            System.out.println(String.format("%s Honeypot running on port %d", serviceType, port));
            logEntries.add(new LogEntry(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), 
                "Server", serviceType, "Honeypot started"));

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket, serviceType)).start();
            }
        } catch (IOException e) {
            LOGGER.severe("Server error on port " + port + ": " + e.getMessage());
        }
    }

    static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final String serviceType;

        public ClientHandler(Socket socket, String serviceType) {
            this.clientSocket = socket;
            this.serviceType = serviceType;
        }

        @Override
        public void run() {
            String clientIP = clientSocket.getInetAddress().getHostAddress();
            int clientPort = clientSocket.getPort();
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

            try (
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))
            ) {
                String connectionMsg = String.format("New %s connection from %s:%d", serviceType, clientIP, clientPort);
                LOGGER.info(connectionMsg);
                logEntries.add(new LogEntry(timestamp, clientIP, serviceType, connectionMsg));
                commonIPs.merge(clientIP, 1, Integer::sum);

                switch (serviceType) {
                    case "SSH":
                        handleSSH(out, in, clientIP);
                        break;
                    case "HTTP":
                        handleHTTP(out, in, clientIP);
                        break;
                    case "FTP":
                        handleFTP(out, in, clientIP);
                        break;
                    case "RDP":
                        handleRDP(out, in, clientIP);
                        break;
                }

            } catch (IOException e) {
                LOGGER.warning("Error handling client " + clientIP + ": " + e.getMessage());
                logEntries.add(new LogEntry(timestamp, clientIP, serviceType, "Error: " + e.getMessage()));
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    LOGGER.warning("Error closing client socket: " + e.getMessage());
                }
            }
        }

        private void handleSSH(PrintWriter out, BufferedReader in, String clientIP) throws IOException {
            out.println("SSH-2.0-OpenSSH_7.4p1");
            out.println("Username: ");
            String username = in.readLine();
            logAndTrack("SSH Username attempt: " + username, clientIP, "SSH", username, null);

            out.println("Password: ");
            String password = in.readLine();
            logAndTrack("SSH Password attempt: " + password, clientIP, "SSH", username, password);

            handleAttempts(out, clientIP, "SSH");
        }

        private void handleFTP(PrintWriter out, BufferedReader in, String clientIP) throws IOException {
            out.println("220 Welcome to Fake FTP Server");
            String input = in.readLine();
            if (input != null && input.startsWith("USER ")) {
                String username = input.substring(5);
                logAndTrack("FTP Username attempt: " + username, clientIP, "FTP", username, null);
                out.println("331 Please specify the password.");
                
                input = in.readLine();
                if (input != null && input.startsWith("PASS ")) {
                    String password = input.substring(5);
                    logAndTrack("FTP Password attempt: " + password, clientIP, "FTP", username, password);
                    handleAttempts(out, clientIP, "FTP");
                }
            }
        }

        private void handleRDP(PrintWriter out, BufferedReader in, String clientIP) throws IOException {
            out.println("RDP Fake Server - Enter credentials");
            out.println("Username: ");
            String username = in.readLine();
            logAndTrack("RDP Username attempt: " + username, clientIP, "RDP", username, null);

            out.println("Password: ");
            String password = in.readLine();
            logAndTrack("RDP Password attempt: " + password, clientIP, "RDP", username, password);

            handleAttempts(out, clientIP, "RDP");
        }

        private void handleHTTP(PrintWriter out, BufferedReader in, String clientIP) throws IOException {
            String request = in.readLine();
            logEntries.add(new LogEntry(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), 
                clientIP, "HTTP", "Request: " + request));

            int attempts = failedAttempts.getOrDefault(clientIP, 0);

            if (request != null && request.contains("/logs")) {
                serveLogTable(out);
            } else if (request != null && (request.contains("POST") || request.contains("/login"))) {
                attempts++;
                failedAttempts.put(clientIP, attempts);

                String line;
                StringBuilder postData = new StringBuilder();
                while ((line = in.readLine()) != null && !line.isEmpty()) {
                    postData.append(line);
                }
                if (postData.length() > 0) {
                    LOGGER.info("HTTP POST data from " + clientIP + ": " + postData.toString());
                    logEntries.add(new LogEntry(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), 
                        clientIP, "HTTP", "POST data: " + postData.toString()));
                    parsePostData(postData.toString(), clientIP);
                }
                serveFile(out, "index.html", attempts >= MAX_ATTEMPTS ? "Account locked due to too many attempts." : "Invalid credentials.");
            } else {
                serveFile(out, "index.html", null);
            }
        }

        private void handleAttempts(PrintWriter out, String clientIP, String service) {
            int attempts = failedAttempts.getOrDefault(clientIP, 0) + 1;
            failedAttempts.put(clientIP, attempts);

            if (attempts >= MAX_ATTEMPTS) {
                out.println("Too many failed attempts. Try again later.");
                LOGGER.warning(service + " Lockout triggered for " + clientIP + " after " + attempts + " attempts");
                logEntries.add(new LogEntry(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), 
                    clientIP, service, "Lockout triggered after " + attempts + " attempts"));
            } else {
                out.println("Login failed. Incorrect username or password.");
            }
        }

        private void logAndTrack(String detail, String clientIP, String service, String username, String password) {
            LOGGER.info(detail + " from " + clientIP);
            logEntries.add(new LogEntry(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), 
                clientIP, service, detail));
            if (username != null) commonUsernames.merge(username, 1, Integer::sum);
            if (password != null) commonPasswords.merge(password, 1, Integer::sum);
        }

        private void parsePostData(String postData, String clientIP) {
            String[] pairs = postData.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=");
                if (keyValue.length == 2) {
                    if (keyValue[0].equalsIgnoreCase("username")) {
                        commonUsernames.merge(keyValue[1], 1, Integer::sum);
                    } else if (keyValue[0].equalsIgnoreCase("password")) {
                        commonPasswords.merge(keyValue[1], 1, Integer::sum);
                    }
                }
            }
        }

        private void serveFile(PrintWriter out, String fileName, String errorMessage) throws IOException {
            File file = new File(fileName);
            if (!file.exists()) {
                out.println("HTTP/1.1 404 Not Found");
                out.println("Content-Type: text/html");
                out.println("");
                out.println("<h1>404 Not Found</h1><p>File not found on server.</p>");
                return;
            }

            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println("");

            try (BufferedReader fileReader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = fileReader.readLine()) != null) {
                    if (errorMessage != null && line.contains("id=\"error\"")) {
                        out.println("<p style=\"color: red;\" id=\"error\">" + errorMessage + "</p>");
                    } else {
                        out.println(line);
                    }
                }
            }
        }

        private void serveLogTable(PrintWriter out) {
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println("");

            out.println("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Honeypot Logs</title>");
            out.println("<style>table { width: 90%; margin: 20px auto; border-collapse: collapse; }");
            out.println("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
            out.println("th { background-color: #f2f2f2; } tr:nth-child(even) { background-color: #f9f9f9; }</style>");
            out.println("</head><body><h1>Honeypot Activity Logs</h1><table>");
            out.println("<tr><th>Timestamp</th><th>IP Address</th><th>Service</th><th>Details</th></tr>");

            synchronized (logEntries) {
                for (LogEntry entry : logEntries) {
                    out.println("<tr><td>" + entry.timestamp + "</td><td>" + entry.ip + "</td><td>" + entry.serviceType + "</td>" +
                        "<td>" + entry.details + "</td></tr>");
                }
            }
            out.println("</table>");

            out.println("<h2>Attack Analysis</h2>");
            out.println("<h3>Most Common IP Addresses</h3><ul>");
            commonIPs.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed()).limit(5)
                .forEach(e -> out.println("<li>" + e.getKey() + ": " + e.getValue() + " attempts</li>"));
            out.println("</ul>");

            out.println("<h3>Most Common Usernames</h3><ul>");
            commonUsernames.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed()).limit(5)
                .forEach(e -> out.println("<li>" + e.getKey() + ": " + e.getValue() + " attempts</li>"));
            out.println("</ul>");

            out.println("<h3>Most Common Passwords</h3><ul>");
            commonPasswords.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed()).limit(5)
                .forEach(e -> out.println("<li>" + e.getKey() + ": " + e.getValue() + " attempts</li>"));
            out.println("</ul>");

            out.println("</body></html>");
        }
    }
}