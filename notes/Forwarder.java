import java.io.*;
import java.net.*;
import java.util.logging.*;
import javafx.application.*;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.*;
import javafx.stage.*;
import javax.net.ssl.*;

/**
 * A utility to spy on JAX-RS connections.
 * This class has a main method. Run it directly.
 * <p>
 * When you connect to http://localhost:8081/ a new connection to
 * https://test-api.pin.net.au/ is established. Data is forwarded between the 
 * two connections. Any data is also displayed on the screen and at the same 
 * time any instances of the server name are substituted in the communication
 * to hide the fact that proxying has happened.
 */
public class Forwarder extends Application {
    
    // Configuration -----------------------------------------------------------
    
    // This is the local socket that the Forwarder listens to:
    private static final String localHost = "localhost";
    private static final int listenPort = 8081;
    
    // This is the remote server that the connections will be fowarded to:
    private static final String remoteHost = "test-api.pin.net.au";
    private static final boolean useSSL = true;
    private static final int remotePort = 443;
    
    // The search/replace pattern ----------------------------------------------
    
    private static final String search = localHost + (listenPort == 80 ? "" : ":" + listenPort);
    private static final String replace = remoteHost + (remotePort == (useSSL ? 443 : 80) ? "" : ":" + remotePort);
    
    private static final byte[] searchBytes = search.getBytes();
    private static final byte[] replaceBytes = replace.getBytes();
    
    // User interface constants ------------------------------------------------
    
    private static final String TITLE_MESSAGE = "Network Interceptor";
    private static final String INFO_MESSAGE = "Listening at http://" + search + "/ and forwarding to " + (useSSL ? "https" : "http") + "://" + replace + "/";
    private static final String CONNECT_MESSAGE = "[New Connection]\n";
    private static final String ERROR_MESSAGE = "\n[Connection Error: %s]\n";
    private static final String CLOSE_MESSAGE = "\n[Connection Closed]\n";
    private static final String USE_FONT = "System";
    
    // Internal state ----------------------------------------------------------
    
    /**
     * If true, the application is shutting down
     */
    private volatile boolean shutdown = false;
    
    /**
     * The TextArea to show incoming requests.
     */
    private TextArea left;
    
    /**
     * A Queue of characters to be added to the left TextArea.
     */
    private StringBuilder leftQueue;
    
    /**
     * The TextArea to show responses from the remote server.
     */
    private TextArea right;
    
    /**
     * A Queue of characters to be added to the right TextArea
     */
    private StringBuilder rightQueue;
    
    
    /**
     * Application entry point.
     * The arguments are ignored.
     */
    public static void main(String[] args) {
        launch(Forwarder.class);
    }
    
    /**
     * Initialize the user interface
     */
    @Override
    public void start(Stage stage) {
        // Set up user interface
        stage.setTitle(TITLE_MESSAGE);
        Label title = new Label(TITLE_MESSAGE);
        title.setFont(Font.font(USE_FONT, FontWeight.BOLD, 18));
        Label info = new Label(INFO_MESSAGE);
        
        // Create GUI components for displaying network activity
        left = new TextArea();
        left.setEditable(false);
        leftQueue = new StringBuilder();
        right = new TextArea();
        right.setEditable(false);
        rightQueue = new StringBuilder();

        // Layout
        GridPane grid = new GridPane();
        GridPane.setConstraints(title, 0, 0, 2, 1, HPos.LEFT, VPos.TOP);
        GridPane.setConstraints(info, 0, 1, 2, 1, HPos.LEFT, VPos.TOP);
        GridPane.setConstraints(left, 0, 2, 1, 1, HPos.CENTER, VPos.CENTER, Priority.ALWAYS, Priority.ALWAYS);
        GridPane.setConstraints(right, 1, 2, 1, 1, HPos.CENTER, VPos.CENTER, Priority.ALWAYS, Priority.ALWAYS);
        
        // Display
        grid.getChildren().addAll(title, info, left, right);
        stage.setScene(new Scene(grid));
        stage.show();
        stage.setOnCloseRequest(e -> shutdown = true);
        
        // Start the network server
        new Thread(this::serve).start();
    }
    
    /**
     * Listen for connections on the local host and forwards those connections 
     * to a remote server.
     * This blocks so it should be run on its own thread.
     */
    public void serve() {
        try (ServerSocket serverSocket = new ServerSocket(listenPort)) {
            serverSocket.setSoTimeout(500); // Check for shutdown every 500ms
            while (true) {
                try {
                    // Listen for an incoming connection
                    Socket local = serverSocket.accept();
                    
                    // Setup outgoing connection
                    Socket remote;
                    if (useSSL)
                        remote = SSLSocketFactory.getDefault().createSocket(remoteHost, remotePort);
                    else
                        remote = new Socket(remoteHost, remotePort);
                    
                    // Check for shutdown every 500ms
                    local.setSoTimeout(500); 
                    remote.setSoTimeout(500);

                    // Forward requests from the local client to the remote server
                    new Thread(new ConnectionForwarder(local, remote, left, leftQueue)).start();

                    // Forward responses from the remote server to the local client
                    new Thread(new ConnectionForwarder(remote, local, right, rightQueue)).start();
                    
                } catch (InterruptedIOException iioe) {
                    // We've encountered a socket timeout
                    if (shutdown)
                        return;
                }
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
    
    /**
     * A helper class that forwards data from an input stream to an output 
     * stream, while logging the intercepted data to a TextArea.
     */
    private class ConnectionForwarder implements Runnable {
        
        private final Socket from;
        private final Socket to;
        private final TextArea textArea;
        private final StringBuilder queue;

        private ConnectionForwarder(Socket from, Socket to, TextArea textArea, StringBuilder queue) {
            this.from = from;
            this.to = to;
            this.textArea = textArea;
            this.queue = queue;
        }
        
        @Override
        public void run() {
            try {
                InputStream in = new BufferedInputStream(from.getInputStream());
                OutputStream out = new BufferedOutputStream(to.getOutputStream());
                writeString(textArea, queue, CONNECT_MESSAGE);
                forward(textArea, queue, in, out);
                writeString(textArea, queue, CLOSE_MESSAGE);
            } catch (IOException ex) {
                // This is a hack to tidy up the exception that occurs when reading from a closed socket
                if ("Socket Closed".equalsIgnoreCase(ex.getMessage())) {
                    writeString(textArea, queue, CLOSE_MESSAGE);
                } else {
                    writeString(textArea, queue, String.format(ERROR_MESSAGE, ex.getMessage()));
                    ex.printStackTrace();
                }
            }
        }
        
    }
   
    /**
     * Read from the input stream, write the the output stream and the logStream.
     * Also substitutes text matching searchBytes for replaceBytes.
     */
    private void forward(TextArea textArea, StringBuilder queue, InputStream in, OutputStream out) throws IOException {
        byte[] check = new byte[searchBytes.length];
        int index = 0;
        int length = 0;
       
        while (true) {
            
            int next;
            
            // Keep trying to get the next byte from the input stream
            // Exit the thread if we're shutting down
            while (true) {
                try {
                    next = in.read();
                    break;
                } catch (InterruptedIOException iioe) {
                    if (shutdown)
                        return;
                }
            }
            
            // At the end of the input stream?
            if (next == -1)
                break;
          
            // Write to the circular buffer
            check[index] = (byte)next;
            index = (index + 1) % check.length;
            length++;
           
            // Is the buffer now full?
            if (length == check.length) {
                // Check if it is a match
                boolean same = true;
                for (int i=0; i<length; i++) {
                    if (check[(index +  i) % check.length] != searchBytes[i]) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    // Identical - so write out the replacement
                    out.write(replaceBytes);
                    for (byte value : replaceBytes)
                        writePrintable(textArea, queue, value);
                    length = 0;
                } else {
                    // Different - so just advance one character
                    byte value = check[index];
                    out.write(value);
                    length--;
                    writePrintable(textArea, queue, value);
                }
            }
           
            // Is there more data queued up?
            if (in.available() == 0) {
                // How about if we wait a little while?
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    // do nothing
                }
                // Still nothing?
                if (in.available() == 0) {
                    // Then write everything we've got, ignoring the potential
                    // string replacement
                    index = (index - length + check.length) % check.length;
                    for (int i=0; i<length; i++) {
                        byte value = check[(index + i) % check.length];
                        out.write(value);
                        writePrintable(textArea, queue, value);
                    }
                    length = 0;
                }
                out.flush();
            }
        }
        
        // The input stream is closed, so just write out anything queued up
        index = (index - length + check.length) % check.length;
        for (int i=0; i<length; i++) {
            byte value = check[(index + i) % check.length];
            out.write(value);
            writePrintable(textArea, queue, value);
        }
        out.flush();
        
        // It would be nice to do a shutdownOutput() here
        // Unfortunately, SSLSocket doesn't appear to provide a way to do this 
        // cleanly so instead, I'll wait for a two second delay and then just
        // close it down
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ex) {
            // Do nothing
        }
        out.close();
    }
   
    /**
     * Write a string to a TextArea via the TextArea's queue.
     */
    private void writeString(TextArea textArea, StringBuilder queue, String value) {
        synchronized (queue) {
            // We only need to call runLater if this is the first character getting queued up
            if (queue.length() == 0)
                Platform.runLater(() -> processQueue(textArea, queue));
            
            // Add the value to the queue
            queue.append(value);
        }
    }
    
    /**
     * Write printable characters to a TextArea via the TextArea's queue. 
     * Converts 'special' characters into spaces.
     */
    private void writePrintable(TextArea textArea, StringBuilder queue, int value) {
        synchronized (queue) {
            // We only need to call runLater if this is the first character getting queued up
            if (queue.length() == 0)
                Platform.runLater(() -> processQueue(textArea, queue));
            
            // Add the value to the queue
            if ((value < ' ' || value > '~') && value != '\n')
                queue.append(' ');
            else
                queue.append((char)value);
        }
    }
    
    /**
     * Copies queued up text data into a TextArea.
     * This method should be called from the JavaFX UI thread.
     */
    private void processQueue(TextArea textArea, StringBuilder queue) {
        synchronized (queue) {
            if (queue.length() > 0) {
                textArea.appendText(queue.toString());
                queue.setLength(0);
            }
        }
    }

}
