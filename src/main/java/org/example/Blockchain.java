/*--------------------------------------------------------

1. Name / Date: Bramhashree Manoharan / 25-05-2022

2. Java version used: Java 17

3. Precise command-line compilation examples / instructions:

javac -cp "gson-2.8.2.jar" BlockJ.java

4. Precise examples / instructions to run this program:

In separate shell windows:

java -cp ".;gson-2.8.2.jar" Blockchain 0
java -cp ".;gson-2.8.2.jar" Blockchain 1
java -cp ".;gson-2.8.2.jar" Blockchain 2

5. List of files needed for running the program.
 a. Blockchain.java
 b. BlockInput0.txt, BlockInput1.txt, BlockInput2.txt
 c. gson-2.8.2 jar file

5. Notes:
   I am able to produce the final Json file successfully.

   But Sometimes, i would say may be once in 5 times , I get the below exception in process 2 and it stops running
   java.security.InvalidKeyException: Missing key encoding

Reference:
  https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @author JJ
  https://dzone.com/articles/generate-random-alpha-numeric  by Kunal Bhatia  Â·  Aug. 09, 12 Â· Java Zone
 Reading lines and tokens from a file:
 http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
 Good explanation of linked lists:
 https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
 Priority queue:
 https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html
 https://mkyong.com/java/how-to-parse-json-with-gson/
 http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
 https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
 https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
 https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
 https://www.mkyong.com/java/java-sha-hashing-example/
 https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
 https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html

----------------------------------------------------------*/
package org.example;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

// utility code from BlockInputG.java provided by Prof.Clark Elliott
//This is a POJO class used to hold the various data of the Block which will be later added to the Blockchain
class BlockRecord{

    int BlockNo;
    String BlockID;
    String TimeStamp;
    String VerificationProcessID;
    String PreviousHash;
    String ID;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String RandomSeed;
    String WinningHash;
    String Diag;
    String Treat;
    String Rx;
    Boolean abandoned = false;

    public Boolean isAbandoned() {
        return abandoned;
    }

    public void setAbandoned(Boolean abandoned) {
        this.abandoned = abandoned;
    }

    public int getBlockNo() {
        return BlockNo;
    }

    public void setBlockNo(int no){
        this.BlockNo = no;
    }

    public String getBlockID() {
        return BlockID;
    }

    public void setBlockID(String BID){
        this.BlockID = BID;
    }

    public String getTimeStamp() {
        return TimeStamp;
    }

    public void setTimeStamp(String TS){
        this.TimeStamp = TS;
    }

    public String getVerificationProcessID() {
        return VerificationProcessID;
    }

    public void setVerificationProcessID(String VID){
        this.VerificationProcessID = VID;
    }

    public String getPreviousHash() {
        return this.PreviousHash;
    }

    public void setPreviousHash (String PH){
        this.PreviousHash = PH;
    }

    public String getID() {
        return ID;
    }

    public void setID (String id){
        this.ID = id;
    }

    public String getLname() {
        return Lname;
    }

    public void setLname (String LN){
        this.Lname = LN;
    }

    public String getFname() {
        return Fname;
    }

    public void setFname (String FN){
        this.Fname = FN;
    }

    public String getSSNum() {
        return SSNum;
    }

    public void setSSNum (String SS){
        this.SSNum = SS;
    }

    public String getDOB() {
        return DOB;
    }

    public void setDOB (String RS){
        this.DOB = RS;
    }

    public String getDiag() {
        return Diag;
    }

    public void setDiag (String D){
        this.Diag = D;
    }

    public String getTreat() {
        return Treat;
    }

    public void setTreat (String Tr){
        this.Treat = Tr;
    }

    public String getRx() {
        return Rx;
    }

    public void setRx (String Rx){
        this.Rx = Rx;
    }

    public String getRandomSeed() {
        return RandomSeed;
    }

    public void setRandomSeed (String RS){
        this.RandomSeed = RS;
    }

    public String getWinningHash() {
        return WinningHash;
    }

    public void setWinningHash (String WH){
        this.WinningHash = WH;
    }

}

// utility code from bc.java provided by Prof.Clark Elliott
//Ports class is used to declare the respective ports for various servers which handle the public keys,
// multicasting the unverified blocks, multicasting the verified blocks and also for listening the start signal
//once Process 2 is initiatied
class Ports{
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;
    public static int InitServerPortBase = 4640;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;
    public static int InitServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + (Blockchain.PID * 1000);
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID * 1000);
        BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID * 1000);
        InitServerPort = InitServerPortBase + (Blockchain.PID * 1000);
    }
}

//This class is created to hold the Public Key Object which has the information that which public key linked
//to which ProcessIDs
class PKey {
    String pubKey;
    int processID;

    public String getPubKey() {
        return pubKey;
    }

    public void setPubKey(String pubKey) {
        this.pubKey = pubKey;
    }

    public int getProcessID() {
        return processID;
    }

    public void setProcessID(int processID) {
        this.processID = processID;
    }
}

//This InitServer and InitWorker listens for start signalling, so that all processes can start the work at the same time
//So Once the main function runs, we check if the PID is 2, and if it is, a start message is multicasted
//to all the processes, and this server listens for that start message and helps the processes to start at the same time.
class InitServer implements Runnable {

    class InitWorker extends Thread {
        Socket socket;
        public InitWorker(Socket socket){
            this.socket = socket;
        }
        public void run(){
            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                Blockchain.init = in.readLine();
            }catch(IOException e){System.out.print(e);}
        }
    }

    public void run(){
        int q_len = 6;
        Socket socket;

        try{
            ServerSocket servsock = new ServerSocket(Ports.InitServerPort, q_len);
            while (true) {
                socket = servsock.accept();
                new InitWorker(socket).start();
            }
        }catch(IOException e){
            e.printStackTrace();
        }
    }
}

// utility code from bc.java provided by Prof.Clark Elliott
//This Server listens to the unverified blocks, once it listens, it starts a unverified block worker thread
//which is responsible for reading the incoming blocks
class UnverifiedBlockServer implements Runnable {
    int q_len = 6;
    Socket socket;

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2)
        {
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };

// The worker thread reads the incoming unverified blocks  and puts the block record data in a priority queue,
// This is later poped by the processes to solve.
    class UBWorker extends Thread {
        Socket socket;

        public UBWorker(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String reader = in.readLine();
                Gson gson = new Gson();
                BlockRecord blockRecordIn = gson.fromJson(reader, BlockRecord.class);
                Blockchain.ourPriorityQueue.add(blockRecordIn);
            } catch (IOException exception) {
                System.out.print(exception);
            }
        }
    }

    public void run() {
        try{
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                socket = UVBServer.accept();
                new UBWorker(socket).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

// utility code from bc.java provided by Prof.Clark Elliott
// This class reads the incoming public keys and adds it to the
// Blockchain public key array to use it futher
class PublicKeyWorker extends Thread {
    Socket keySock;
    public PublicKeyWorker(Socket s){
        keySock = s;
    }
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
            String data = in.readLine();
            Gson gson = new Gson();
            PKey pubKey = gson.fromJson(data, PKey.class);
            Blockchain.pubKeyArr.add(pubKey);
        }catch(IOException e){System.out.print(e);}
    }
}

// utility code from bc.java provided by Prof.Clark Elliott
//This worker class is used to read all the incoming blockchain records,
//converts it from JSON to Java object and adds all the block records to the Blockchain list
class PublicKeyServer implements Runnable {
    public void run(){
        int q_len = 6;
        Socket keySock;
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                keySock = servsock.accept();
                new PublicKeyWorker(keySock).start();
            }
        }catch(IOException e){System.out.print(e);}
    }
}

//Blockchain Class starts here which has lot of helper methods and the main function
//to run the blockchain program
//Most of the helper functions and code is taken from the utility programs provided by prof.Clark Elliott
public class Blockchain {

    // here we are specifying the index numbers based on which we get the data from the text file
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;
    static String JsonOpen = "[";
    static String JsonClose = "]";
    static int PID = 0;
    public static List<PKey> pubKeyArr = new ArrayList<>(); //array to hold the publicKeys
    public static PrivateKey privKey;
    // Initially the init string is kept false, this is changes true only when Process 2 is initiated
    public static String init = "false";
    private static String FILENAME;
    static List<BlockRecord> blockRecArr = new ArrayList<BlockRecord>(); // to maintain a list of blocks
        private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // this is used as a random seed
    public static LinkedList<BlockRecord> blockChain = new LinkedList<>(); //Blockchain is maintained once and when a block is verified
    //This helper function is used to convert the byte array to string
    public static String ByteArrayToString(byte[] ba) {
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for (int i = 0; i < ba.length; i++) {
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }

    //This priority queue is where we add all the unverified blocks and all the processes have access to this while solving the puzzle
    static final Queue<BlockRecord> ourPriorityQueue = new PriorityQueue<>(250, UnverifiedBlockServer.BlockTSComparator);

    //This is a helper method that coverts all the blockrecords into String
    public static String formatToString(BlockRecord block){
        String formatToString =
                block.getTimeStamp() +
                        block.getBlockNo() +
                        block.getBlockID() +
                        block.getID() +
                        block.getPreviousHash() +
                        block.getFname() +
                        block.getLname() +
                        block.getDOB() +
                        block.getSSNum() +
                        block.getVerificationProcessID() +
                        block.getDiag() +
                        block.getTreat() +
                        block.getRx() +
                        block.getTimeStamp();
        return formatToString;
    }

    // This method is taken from BlockJ.java provided by prof.Clark Elliott, where we use this for our block 0.
    // With the help of MessageDigest class, we convert the hashbytes to hex format
    // and later change it to String which can be used for the next block as the previous block's winning string
    public static String hashBlock(String blockContents){
        String SHA256String = "";
        try{
            MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
            ourMD.update (blockContents.getBytes());
            byte byteData[] = ourMD.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            SHA256String = sb.toString();
        } catch(NoSuchAlgorithmException x){};
        return SHA256String.toUpperCase();
    }

    // Utility method from BlockJ.java provided by Prof.Clark Elliott
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
    return (keyGenerator.generateKeyPair());
    }

    // Utility method from BlockJ.java provided by Prof.Clark Elliott
    //This helper method recieves the data, updates it and signs it using the private key
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {

        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    // Utility method from BlockJ.java provided by Prof.Clark Elliott
    // This method is used to verify whether the given public key matches with the signed private key
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
    }

    // Utility method from bc.java provided by Prof.Clark Elliott
    //This method is used to multicast the unverified blocks to all the processes
    //Converts the blok record into Json objects, creates connections to all processes
    //and sends the data
    public static void UBMultiCast(BlockRecord block, int ServerBase) throws Exception {
        Socket sock;
        PrintStream toServer;

        try{
            Gson gson = new GsonBuilder().create();
            String data = gson.toJson(block);
            for(int i=0; i< 3; i++){
                sock = new Socket("localhost", ServerBase + (i * 1000));
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(data); toServer.flush();
            }

        }catch (Exception x) {x.printStackTrace ();}
    }

    // Utility method from WorkB.java provided by Prof.Clark Elliott
    //This helper function creates a String with random letters and numbers which is used as a random seed
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    // Utility method from WorkB.java provided by Prof.Clark Elliott
    //This method is the core functionality of the Blockchain program where all the processes compete to solve the puzzle
    //A random seed is appended to the block data and the hash value which is less than the limit set will be the winning hash
    //that solved the puzzle. This limit in the below function is set 20000, but can be decreased so that the puzzle solving
    // competition can be made even more harder. Once the hash value is less than the limit, then that block along with the
    //winning hash and random seed is added to the blockchain, where the processes take up the next input block and previous hash
    //and continue to solve the next puzzle
    public static BlockRecord doWork(BlockRecord blockRec){
        int workNumber = 0;

        String randString = "";
        String concatString = "";
        String stringOut = "";

        //Here we assign the previous hash to the block to start the puzzle solving method
        blockRec.setVerificationProcessID(Integer.toString(Blockchain.PID));
        blockRec.setBlockNo(Blockchain.blockChain.get(0).getBlockNo() + 1);
        blockRec.setPreviousHash(Blockchain.blockChain.get(0).getWinningHash());

        String data = formatToString(blockRec);
        try {
            while (true) {
                randString = randomAlphaNumeric(8);
                concatString = data + randString;
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));

                stringOut = ByteArrayToString(bytesHash);
                System.out.println("Hash is: " + stringOut);

                //Here the first four digits are taken and converted to int to get the worknumber
                //which will be compared with the limit
                workNumber = Integer.parseInt(stringOut.substring(0,4),16);
                System.out.println("First 16 bits in Hex and Decimal: " + stringOut.substring(0,4) +" and " + workNumber);

                if (!(workNumber < 20000)){
                    // Since the worknumber is not less than the limit, we continue to solve the puzzle
                    System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
                }
                if (workNumber < 20000){
                    //If the above condition is acheived, we have solved the puzzle and hence winning hash and random seed
                    //are added to the block record
                    System.out.format("%d IS less than 20,000 so puzzle solved!\n", workNumber);
                    blockRec.setRandomSeed(randString);
                    blockRec.setWinningHash(stringOut);
                    break;
                }
                for (int i = 0, blockChainSize = blockChain.size(); i < blockChainSize; i++) {
                    BlockRecord b = blockChain.get(i);
                    //here we check if the blockID is already present in the block chain, that is if
                    //theres already another procees which has solved the pyzzle, if so then we need to abandon
                    //the verification effort and take up the next block in the queue and work on it
                    if (blockRec.getBlockID().equals(b.getBlockID())) {
                        BlockRecord check = new BlockRecord();
                        check.setAbandoned(true);
                        System.out.println("This Block is already updated, so abandoning verification effort");
                        return check;
                    }
                }
                try{Thread.sleep(4000);}catch(InterruptedException e){
                    e.printStackTrace();
                }
            }
        }catch(Exception ex) {ex.printStackTrace();}
        return blockRec;
    }

    //get public key from the process that took this block
    public static String getPublicKey(BlockRecord rec) {

        String pkHolder = "";
        for (PKey pubKey : pubKeyArr) {
            if (Integer.toString(pubKey.getProcessID()).equals(rec.getVerificationProcessID())) {
                pkHolder = pubKey.getPubKey();
            }
        }
        return pkHolder;
    }
    //this is the main method of the blockchain program
    public static void main(String args[]) throws Exception {

        //Checking if any arguments are passed, if not then assigning 0 by default
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);

        //Initializing the public key object for the processes
        Random rand = new Random();
        long randomNum = rand.nextInt(1000);
        KeyPair keyPair = generateKeyPair(randomNum);
        privKey = keyPair.getPrivate();
        byte[] bytePubkey = keyPair.getPublic().getEncoded();
        String stringKey = Base64.getEncoder().encodeToString(bytePubkey);
        PKey pk = new PKey();
        pk.setPubKey(stringKey); pk.setProcessID(PID);

        PKey pkey = pk;

        System.out.println(" Bramhashree Manoharan's Blockchain System. Use Control-C to stop the process.\n");
        System.out.println("Using processID " + PID + "\n");

        new Ports().setPorts();
        //Starting the server to Listen for the start message
        new Thread(new InitServer()).start();
        //Starting the server to Listen for the public keys from other processes
        new Thread(new PublicKeyServer()).start();
        //Starting the server to Listen for the incoming unverified blocks
        new Thread(new UnverifiedBlockServer()).start();

        System.out.println("Servers are up and listening..");

        //This is the signal to let know the processes to start, when processes id 2 is initiated then
        //the message true is multi casted to all the ports to indicate the start process
        if (PID == 2){
            Socket mainsock;
            PrintStream ps;
            try{
                for(int i=0; i< 3; i++){
                    mainsock = new Socket("localhost", Ports.InitServerPortBase + (i * 1000));
                    ps = new PrintStream(mainsock.getOutputStream());
                    ps.println("true");
                    ps.flush();
                }
            }catch (Exception e) {
                e.printStackTrace ();
            }
        }
        try{
            Thread.sleep(1000);
        }catch(Exception e){
            e.printStackTrace();
        }

        //this global value is set to true once the signal is sent and then the block chain process is initiated
        //where the public keys are multicasted first
        if (init.equals("true")){
            Socket keysock;
            PrintStream ps;
            Gson gson = new GsonBuilder().create();
            //the public keys are converted to String and sent to respective ports of each processes
            String JSON = gson.toJson(pk);
            try{
                for(int i=0; i< 3; i++){
                    keysock = new Socket("localhost", Ports.KeyServerPortBase + (i * 1000));
                    ps = new PrintStream(keysock.getOutputStream());
                    ps.println(JSON);
                    ps.flush();
                }
            }catch (Exception x) {x.printStackTrace ();
            }

            try{
                Thread.sleep(1000);
            }catch(InterruptedException e){
                e.printStackTrace();
            }

            //A dummy block 0 is initiated with previous hash 0 and random data is put into the block data
            //so that a winning hash is produced and that can be used as the previous hash when we read the block
            //data from the files
            LinkedList<BlockRecord> blockRec00 = new LinkedList<>();

            UUID BinaryUUID = UUID.randomUUID();
            String suuid00 = BinaryUUID.toString();
            Date date00 = new Date();
            String T100 = String.format("%1$s %2$tF.%2$tT", "", date00);
            String TimeStampString00 = T100 + "." + Blockchain.PID + "\n";

            BlockRecord dummy = new BlockRecord();

            dummy.setVerificationProcessID("0");
            dummy.setBlockID(suuid00);
            dummy.setBlockNo(0);
            dummy.setTimeStamp(TimeStampString00);
            dummy.setPreviousHash("0");
            dummy.setRandomSeed("47P14BY3");
            String blockData = formatToString(dummy) + dummy.getRandomSeed();
            dummy.setWinningHash(hashBlock(blockData));

            blockRec00.add(dummy);
            blockChain = blockRec00;

            //Based on the process IDs, the files are read by the respective processes
            List<BlockRecord> recordList = new ArrayList<>();
            switch(PID){
                case 1: FILENAME = "BlockInput1.txt"; break;
                case 2: FILENAME = "BlockInput2.txt"; break;
                default: FILENAME= "BlockInput0.txt"; break;
            }
            // as we read the files,we first put into an unverified block
            System.out.println("Input file- " + FILENAME);
            try {
                BufferedReader br = new BufferedReader(new FileReader(FILENAME));
                String[] tokens = new String[10];
                String InputLineStr;
                String suuid;
                UUID idA;
                BlockRecord tempRec;
                int n = 0;
                //reading every line from the file and consider it as a block record
                while ((InputLineStr = br.readLine()) != null) {
                    BlockRecord BR = new BlockRecord();
                    try{Thread.sleep(1001);}catch(InterruptedException e){}
                    Date date = new Date();
                    String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                    String TimeStampString = T1 + "." + PID;
                    BR.setTimeStamp(TimeStampString);
                    BR.setBlockNo(n);

                    suuid = new String(UUID.randomUUID().toString());
                    BR.setBlockID(suuid);
                    //Here we sign with the current process ID which is reading the block to later verify it
                    byte[] digitalSignature = signData(suuid.getBytes(), privKey);
                    String SignedSHA256ID = Base64.getEncoder().encodeToString(digitalSignature);
                    BR.setID(SignedSHA256ID);
                    tokens = InputLineStr.split(" +");
                    BR.setFname(tokens[iFNAME]);
                    BR.setLname(tokens[iLNAME]);
                    BR.setSSNum(tokens[iSSNUM]);
                    BR.setDOB(tokens[iDOB]);
                    BR.setDiag(tokens[iDIAG]);
                    BR.setTreat(tokens[iTREAT]);
                    BR.setRx(tokens[iRX]);
                    BR.setVerificationProcessID(Integer.toString(Blockchain.PID));

                    //Finally add to the list so that this can be multicasted to all the
                    //processes
                    recordList.add(BR);
                    n++;
                }
            } catch (Exception e){System.out.println(e);}

            blockRecArr = recordList;

            //Here we multicast all the unverified blocks to all the processes to start the competition
            for (Iterator<BlockRecord> iterator = blockRecArr.iterator(); iterator.hasNext(); ) {
                BlockRecord block = iterator.next();
                UBMultiCast(block, Ports.UnverifiedBlockServerPortBase);
            }

            try{Thread.sleep(1000);}catch(InterruptedException e){}

            while (true){

                boolean checkBlock = false;
                String pkHolder = "";

                // We can check the number of remainig blocks that are yet to be verified and added to the block
                BlockRecord rec = ourPriorityQueue.poll();
                System.out.println("Yet to Solve " + ourPriorityQueue.size() + " Unverified Blocks");
                //If it is empty, then there are no unverified blocks an we can terminate the process
                BlockRecord verificationDone = new BlockRecord();
                if (rec == null)
                    break;
                pkHolder = getPublicKey(rec);
                boolean verified = false;

                try {
                    //Here we convert the signedId and the public key to bytes for verification purposes
                    //If the verification is successful, we can move forward with the main funtionality, that is
                    //solving the puzzle
                    byte[] signedID = Base64.getDecoder().decode(rec.getID());
                    byte[] bytePubkey2 = Base64.getDecoder().decode(pkHolder);
                    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubkey2);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);
                    verified = verifySig(rec.getBlockID().getBytes(), RestoredKey, signedID);
                }catch (Exception e) {

                }
                if(!verified) {
                    System.out.println("Wrong Signature");
                }

                if(verified){
                    //checking if the block is already solved and added to the blockchain
                    //if so we can skip this and not waste any effort trying to solve already solved puzzle
                    for (BlockRecord block : blockChain) {
                        if (rec.getBlockID().equals(block.getBlockID())) {
                            checkBlock = true;
                            System.out.println("This block is present in blockchain already");
                        }
                    }
                    while (!checkBlock){
                        //Calling doWork method only if the block is not already solved by other processes
                        verificationDone = doWork(rec);
                        //We might start to solve the puzzle and before we solve it, some other process might have
                        //solved the puzzle and added the block to the block chain and hence we check periodically if
                        //the block is solved or not and store in a boolen
                        if (verificationDone.isAbandoned())
                            break;
                        else{
                            //Here we check if the previous hash of the currently verified block and the
                            //winninghash of the block which is in the 0th position, that is the lastly added
                            //block is equal and only if it is, we add it to the block chain
                            if (!((verificationDone.getPreviousHash().equals(blockChain.get(0).getWinningHash())))){
                                for (BlockRecord b: blockChain){
                                    if (b.getBlockID().equals(verificationDone.getBlockID())){
                                        checkBlock = true;
                                    }
                                }
                            }
                            else {
                                //Once the block puzzle is solved, the block is added to the blockchain
                                //Here the blocks are prepended always and hence it is easy for us
                                //to get the previous hash of block0 whenever we start a new block puzzle
                                System.out.println("Verification Done!");
                                blockChain.addFirst(verificationDone);
                                checkBlock = true;

                            }
                        }
                    }
                }
            }
            System.out.println("THE BLOCKCHAIN IS COMPLETED");
        }
        //Once the Blockchain is completed, Finally printing the blockchain records to the JSOM file
        if (Blockchain.PID == 0){
            Gson gsonPretty = new GsonBuilder().setPrettyPrinting().create();
            String toFile = JsonOpen;
            for (Iterator<BlockRecord> iterator = Blockchain.blockChain.iterator(); iterator.hasNext(); ) {
                BlockRecord blockRecord = iterator.next();
                toFile += gsonPretty.toJson(blockRecord);
                if (Blockchain.blockChain.indexOf(blockRecord) != Blockchain.blockChain.size() - 1)
                    toFile += ",";
            }
            toFile = toFile + JsonClose;
            try (FileWriter fw = new FileWriter("BlockchainLedger.json", false)) {
                fw.write(toFile);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
