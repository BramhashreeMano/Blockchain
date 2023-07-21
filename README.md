# Blockchain

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

## References:
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
