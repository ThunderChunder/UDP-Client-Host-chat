/*
Brian Valenzi, bv457, 4776793, Assignment 1 Host <-> Client secure channel
Web resources used:
    https://www.geeksforgeeks.org/sha-1-hash-in-java/
    https://docs.oracle.com/javase/tutorial/java/data/buffers.html
    https://www.baeldung.com/java-base64-encode-and-decode
    #The RC4 resouce was incorrect but i found the library and managed to correct it#
    http://esus.com/encryptingdecrypting-using-rc4/
*/

import java.io.IOException; 
import java.net.DatagramPacket; 
import java.net.DatagramSocket; 
import java.net.InetAddress; 
import java.net.SocketException;
import java.util.Scanner;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Host extends Thread
{ 
    private DatagramSocket dSocket;
    private InetAddress HOST_IP;
    private final int HOST_PORT = 2222;

    private int CLIENT_PORT = 0;
    private InetAddress CLIENT_IP;
    private String CLIENT_IDENTITY = "";

    private final String FILE_NAME = "PASSWORD.txt";
    private boolean KEY_EXCHANGE_SUCCESS = false;
    private Gen dh;
    //false = overwrite and true = append
    private boolean OVER_WRITE_FILE = false;

    private String password;
    private BigInteger g;
    private BigInteger p;

    private BigInteger SESSION_KEY = null;
    private boolean CONNECTED = false;
    private boolean THREAD_START_LOG = true;

    public Host(boolean initStage)
    {

        try
        {
            HOST_IP = InetAddress.getLocalHost();
            if(initStage)
	    	{
	    		storePassword();
		    	GenerateAndStoreDHParameters();

	    	}
	    	else
	    	{
	    		dSocket = new DatagramSocket(HOST_PORT, HOST_IP);
	    		listenForClient();
	    	}
        }
        catch(Exception e)
        {
            System.out.println(e);
    	}
     
    }
    //Listen for initial client UDP packet
    public void listenForClient()
    {
        byte receive[] = new byte[2000];
        DatagramPacket dpReceive = new DatagramPacket(receive, receive.length);
        while(true)
        {
            System.out.println('\n'+"Waiting for client packet..."+'\n');
            try
            {	
                //poll until client sends UDP packet
                while(CLIENT_PORT == 0)
                {
                    dSocket.receive(dpReceive);
                    //Retrieves Client address from UDP packet to respond back
                    if(dpReceive.getPort() != 0)
                    {
                        CLIENT_PORT = dpReceive.getPort();
                        CLIENT_IP = dpReceive.getAddress();
                        System.out.println("\n"+"Client packet received from IP: "+CLIENT_IP+":"+CLIENT_PORT+"\n");
                        System.out.println("\tClient: " + data(receive)+'\n');
                        receive = new byte[2000];
                    }
                }
                if(handShakeProtocol())
                {
                	start();
                    startSecureChat();
                    break;
                }
            }
            catch(Exception e){System.out.println(e);}
        }
        deleteClientInfo();
        //close socket after use
        dSocket.close();
    }
    //remove client info from memory
    public void deleteClientInfo()
    {
    	CLIENT_IP = null;
    	CLIENT_PORT = 0;
    	KEY_EXCHANGE_SUCCESS = false;
    	SESSION_KEY = null;
    	CONNECTED = true;
    }
    //This is the diffie-hellman key exchange handshake protocol
    public boolean handShakeProtocol()
    {
        try
        {
            byte receive[] = new byte[2000];
            readFileParams(FILE_NAME);
            String buffer = (p.toString()+","+g.toString());
            String clientgPowEModP = "";
            String temp = "";
            BigInteger clientPreKey = null;
            BigInteger sharedKey = null;
            //Host -> Client: send Diffie hellman parameters (g, p)
            sendUDPPacket(buffer.getBytes(), buffer.getBytes().length, CLIENT_IP, CLIENT_PORT);
            //Client -> Host: receive encrypted g^b mod p
            listenForUDPPackets(receive);
            //decrypted with passwordhash
            clientgPowEModP = new String(rc4.decrypt(receive, password));

            clientPreKey = new BigInteger(clientgPowEModP);
            System.out.println("\tClient: g^b mod p:");
            System.out.println("\t\tCiphertext: "+new String(receive).trim());
            System.out.println("\t\tPlainText: "+clientgPowEModP);
            //generate g^a mod p
            BigInteger e = new Gen("Client").generateExponent();
            BigInteger gPowEModP = g.modPow(e, p);
            //y is string buffer to store g^a mod p
            String y = new String(gPowEModP.toString());
            receive = new byte[2000];
            //encrypt g^a mod p with password hash
            receive = rc4.encrypt(y, password);
            //Host -> Client: send g^a mod p encrypted
            sendUDPPacket(receive, receive.length, CLIENT_IP, CLIENT_PORT);
            //generate session key with client pre key (g^b)^a mod p
            sharedKey = clientPreKey.modPow(e, p);

            System.out.println("\ng^ba mod p: "+sharedKey);

            receive = new byte[2000];
            //listen for key confirmation response
            listenForUDPPackets(receive);
            temp = new String(rc4.decrypt(receive, sharedKey.toString()));

            if(temp.equals("Key Confirmation"))
            {
                //receive = new byte[2000];
                System.out.println("\n\tClient: "+temp+'\n');
                receive = rc4.encrypt("Success", sharedKey.toString());
                sendUDPPacket(receive, receive.length, CLIENT_IP, CLIENT_PORT);
                SESSION_KEY = sharedKey;
                CONNECTED = true;
                return true;
            }
            else
            {
                System.out.println("Client couldnt confirm key");    
                return false;
            }
        }
        catch(Exception e){}
        return false;

    }

    public void readFileParams(String fileName) throws Exception
    {
        BufferedReader fileReader = new BufferedReader(new FileReader(fileName));
        String buffer;
        String pass = "password:";
        String g = "g:";
        String p = "p:";

        while((buffer = fileReader.readLine()) != null)
        {
            if(buffer.contains(pass))
            {
                this.password = buffer.substring(pass.length());
            }
            if(buffer.contains(g))
            {
                this.g = new BigInteger(buffer.substring(g.length()));
            }
            if(buffer.contains(p))
            {
                this.p = new BigInteger(buffer.substring(p.length()));
            }
        }
    }

    private void GenerateAndStoreDHParameters()
    {
        System.out.println('\n'+"Your Diffie Hellman parameters are:");
        dh = new Gen("Host");
        Map<String, BigInteger> params = new HashMap<String, BigInteger>();
        params = dh.getPublicParameters();

        writeToFile(FILE_NAME, "g:"+params.get("g").toString());
        writeToFile(FILE_NAME, "p:"+params.get("p").toString());
    }

    public void storePassword()
    {
        System.out.println('\n'+"Please enter your passphrase/password.");
        Scanner scanner = new Scanner(System.in);
        String passWord = "";
        while(true)
        {
        	passWord = scanner.nextLine();
            if(passWord.length() >= 6)
            {
                passWord = hashString(passWord);
                System.out.println('\n'+"Password Hash: "+passWord+" stored to "+FILE_NAME);    
                writeToFile(FILE_NAME, "password:"+passWord);
                return;
            }
            else
            {
                System.out.println("Please enter 6 or more characters.");
            }
        }
    }
    //writes data to specified file
    public void writeToFile(String fileName, String data)
    {
        try 
        { 
            BufferedWriter fileWriter = new BufferedWriter(new FileWriter(fileName, OVER_WRITE_FILE));
            fileWriter.write(data);
            fileWriter.newLine();
            fileWriter.flush();
            fileWriter.close();
            OVER_WRITE_FILE = true;
        }
        catch(IOException e) 
        {
            System.out.println("Exception thrown in Host.writeToFile(): " + e);
        }
    }
    //hashes string with SHA-1, returns String object
    public String hashString(String passWord)
    {
        String hash = null;
        try 
        { 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 

            byte[] messageDigest = md.digest(passWord.getBytes()); 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashText = no.toString(16); 
  
            // Add 0s to make it 32 bit 
            while (hashText.length() < 32) 
            { 
                hashText = "0" + hashText; 
            }
            hash = hashText;  
        } 
        catch (NoSuchAlgorithmException e) 
        { 
            System.out.println("Exception thrown in Host.hashString(): " + e); 
        } 

        return hash;
    }
    //Begin reading using input, encrypt and send to specfied address
    //This is main thread, polls for using input to send
    public void startSecureChat()
    {
        byte buffer[] = new byte[2000];
        String input = "";
        Scanner scan = new Scanner(System.in);
        while(CONNECTED)
        {
            try
            {
                input = scan.nextLine();
                buffer = rc4.encrypt(input, SESSION_KEY.toString()); 
                sendUDPPacket(buffer, buffer.length, CLIENT_IP, CLIENT_PORT);
                buffer = new byte[2000];
            }
            catch(Exception e){}
        }
        System.out.println("Secure channel closed.");
    }
    //sends byte [] buffer data as UDP packet to specified address and port
    public void sendUDPPacket(byte[] data, int length, InetAddress ip, int port)
    { 
        try
        { 
            DatagramPacket dpSend = new DatagramPacket(data, length, ip, port);  
            dSocket.send(dpSend);
            //clear buffer
            data = new byte[1460];
        }
        catch(Exception e)
        {
            System.out.println(e);
        }
    }
    //listens for UDP packets to bound socket, writing data into byte[]
    public void listenForUDPPackets(byte receive[])
    {
        try
        {
            DatagramPacket dpReceive = new DatagramPacket(receive, receive.length);
            dSocket.receive(dpReceive);
        }
        catch(Exception e)
        {
            System.out.println("Exception "+e);
        }
    }
    //Method that runs when thread is called with this.start()
    //Constantly polls for incoming UDP packets
    public void run()
    {
        System.out.println ("Host secure channel is listening on IP: "+dSocket.getLocalSocketAddress());
        byte receive[] = new byte[1460];
        String temp = "";
        while(CONNECTED)
        {
            try
            {
        		listenForUDPPackets(receive);
                temp = new String(rc4.decrypt(receive, SESSION_KEY.toString()));
                System.out.println("\tClient: ");
                System.out.println("\t\tCipherText: "+new String(receive).trim());
                System.out.println("\t\tPlainText: "+temp);

                if(temp.equals("exit"))
                {
                	receive = new byte[1460];
                	CONNECTED = false;
                	//THREAD_START_LOG = false; 
                	System.out.println("Client Disconnected\nPlease press Enter to listen for new client.");
                } 
 
                receive = new byte[1460];
            }
            catch(Exception e)
            {
                System.out.println("Exception "+e);
                break;
            } 
        }
    } 
  
    // byte data into a string 
    public StringBuilder data(byte[] receive) 
    { 
        if (receive == null) 
            return null; 
        StringBuilder temp = new StringBuilder(); 
        int i = 0; 
        while (receive[i] != 0) 
        { 
            temp.append((char) receive[i]); 
            i++; 
        } 
        return temp; 
    }

    public static void main(String[] args) 
    {
        //pass true to run password and Diffie hellman functions
    	Host temp = new Host(true);
    	while(true)
    	{
    		Host host = new Host(false);
    	}
    }  
}
