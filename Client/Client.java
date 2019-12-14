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
import java.util.Scanner;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Client extends Thread
{ 
    private DatagramSocket dSocket;
    private final int CLIENT_PORT = 1111;
    private InetAddress CLIENT_IP;
    private final int HOST_PORT = 2222;
    private InetAddress HOST_IP;
    private BigInteger SESSION_KEY = null;

    public Client() throws Exception
    {
        try
        {
            CLIENT_IP = InetAddress.getLocalHost();
            HOST_IP = InetAddress.getLocalHost();
            dSocket = new DatagramSocket(CLIENT_PORT);
        }
        catch(Exception e)
        {
            System.out.println(e);
        }
        initClient();
    }

    public void initClient()
    {
        if(handShakeProtocol())
        {
            super.start();
            startSecureChat();
        }
    }
     //This is the diffie-hellman key exchange handshake protocol
     public boolean handShakeProtocol()
    {
        try
        {
            byte receive[] = new byte[2000];
            DatagramPacket dpReceive = new DatagramPacket(receive, receive.length);
            String passHash = "";
            String temp = "";
            Gen dh = new Gen("Client");
            BigInteger hostPreKey = null;
            BigInteger sharedKey = null;

            Scanner scanner = new Scanner(System.in);

            System.out.println("Please enter password/passphrase.");
            passHash = hashString(scanner.nextLine().toString());

            System.out.println("Please enter your identity.");
            temp = scanner.nextLine();

            //Client -> Host: initiate handshake protocol
            sendUDPPacket(temp.getBytes(), temp.getBytes().length, CLIENT_IP, HOST_PORT);

            //Host -> Client: receive Diffie hellman parameters (g, p)
            listenForUDPPackets(receive);

            String[] dParams = data(receive).toString().split(",");
            receive = new byte[2000];
            BigInteger p = new BigInteger(dParams[0]);
            BigInteger g = new BigInteger(dParams[1]);
            BigInteger e = dh.generateExponent();
            //generate g^b mod p
            BigInteger gPowEModP = g.modPow(e, p);

            System.out.println("\n\tHost: Diffie-Hellman parameters:");
            System.out.println("\t\tp: "+p);
            System.out.println("\t\tg: "+g);
            //x is string buffer to store g^b mod p
            String x = new String(gPowEModP.toString());
            //encrypt g^b mod p and store into byte [] with password hash
            receive = rc4.encrypt(x, passHash);
            //Client -> Host: send encrypted g^b mod p
            sendUDPPacket(receive, receive.length, CLIENT_IP, HOST_PORT);
            receive = new byte[2000];
            //Host -> Client: Listen for g^a mod p
            listenForUDPPackets(receive);
            //Decrypt Host message to get g^b mod p with password hash
            temp = new String(rc4.decrypt(receive, passHash));
            hostPreKey = new BigInteger(temp);
            System.out.println("\n\tHost: g^a mod p:");
            System.out.println("\t\tCiphertext:"+new String(receive).trim());
            System.out.println("\t\tPlainText: "+hostPreKey);
            //Generate session key with host pre key (g^a)^b mod p
            sharedKey = hostPreKey.modPow(e, p);

            System.out.println("\ng^ab mod p: "+sharedKey);

            receive = new byte[2000];
            //encrypted message with newly generated session key to confirm key exchange success
            receive = rc4.encrypt("Key Confirmation", sharedKey.toString());
            sendUDPPacket(receive, receive.length, CLIENT_IP, HOST_PORT);
            receive = new byte[2000];
            //Listen for host success confirmation
            listenForUDPPackets(receive);
            //decrypt host message
            temp = new String(rc4.decrypt(receive, sharedKey.toString()));

            if(temp.equals("Success"))
            {
                System.out.println("\n\tHost: "+temp+'\n');
                SESSION_KEY = sharedKey;
                return true;
            }
            else
            {
                //if key exchange
                System.out.println("Unnsuccessful");    
                return false;
            }
        }
        catch(Exception e){System.out.println(e);}
        return false;
    }
    //Begin reading using input, encrypt and send to specfied address
    //This is main thread, polls for using input to send
    public void startSecureChat()
    {
        byte buffer[] = new byte[2000];
        Scanner scanner = new Scanner(System.in);
        String input = "";
        while(true)
        {
            try
            {
                input = scanner.nextLine();

                buffer = rc4.encrypt(input, SESSION_KEY.toString()); 
                sendUDPPacket(buffer, buffer.length, HOST_IP, HOST_PORT);
                buffer = new byte[2000];
                if(input.equals("exit")){System.out.println("Shutting down."); System.exit(0);}
            }
            catch(Exception e)
            {
                System.out.println(e);
            }
        }
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

    //Begin reading using input, encrypt and send to specfied address
    //This is main thread, polls for using input to send
    public void run()
    {
        System.out.println ("Client is listening on IP: "+CLIENT_IP);
        byte receive[] = new byte[1460];
        String temp = "";
        while(true)
        {
            try
            {
                listenForUDPPackets(receive);

                temp = new String(rc4.decrypt(receive, SESSION_KEY.toString()));
                System.out.println("\tHost: ");
                System.out.println("\t\tCipherText: "+new String(receive).trim());
                System.out.println("\t\tPlainText: "+temp);

                // Clear the buffer 
                receive = new byte[1460];
            }
            catch(Exception e)
            {
                System.out.println("Exception "+e);
                break;
            } 
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
    // byte data into a string
    //https://docs.oracle.com/javase/tutorial/java/data/buffers.html 
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

    public static void main(String args[]) throws Exception 
    { 
        Client client = new Client();
    } 
} 