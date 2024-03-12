import java.io.*;

public class Rc6EncDec {
    private static final int w_size = 32;
    private static final int r = 20;
    private static final int size = r * 2 + 4;

    private static int A = 0x00000000;
    private static int B = 0x00000000;
    private static int C = 0x00000000;
    private static int D = 0x00000000;

    private static final int loopSize = w_size/8;

    private static int leftShift(int a, int num) {
        return (a << num) | (a >>> (32 - num));
    }
    //Required Right Rotate function for decryption
    private static int rightShift(int a, int num) {
        return (a >>> num) | (a << (32 - num));
    }

    private static void encrypt(int[] S_array){
        B = B + S_array[0];
        D = D + S_array[1];

        for (int i = 1; i <= r; i++) {
            int t = leftShift((B * (2 * B + 1)), 5);
            int u = leftShift((D * (2 * D + 1)), 5);
            A = leftShift((A ^ t), (u & 0x1f)) + S_array[2 * i];
            C = leftShift((C ^ u), (t & 0x1f)) + S_array[2 * i + 1];
            int temp_value = A;
            A = B;
            B = C;
            C = D;
            D = temp_value;
        }
        A = A + S_array[2 * r + 2];
        C = C + S_array[2 * r + 3];
    }

    private static void decrypt(int[] S_array){
        A = A - S_array[2 * r + 2];
        C = C - S_array[2 * r + 3];

        for (int i = r; i >= 1; i--) {
            int temp_value = D;
            D = C;
            C = B;
            B = A;
            A = temp_value;
            int t = leftShift((B * (2 * B + 1)), 5);
            int u = leftShift((D * (2 * D + 1)), 5);
            C = (rightShift((C - S_array[2 * i + 1]), (t & 0x1f)) ^ u);
            A = (rightShift((A - S_array[2 * i]), (u & 0x1f)) ^ t);
        }

        B = B - S_array[0];
        D = D - S_array[1];
    }

    private static void printOutput(){
        for (int i = 0; i < loopSize; i++) {
            System.out.printf("%02x ", (A >>> (i * 8)) & 0xFF);
        }

        for (int i = 0; i < loopSize; i++) {
            System.out.printf("%02x ", (B >>> (i * 8)) & 0xFF);
        }

        for (int i = 0; i < loopSize; i++) {
            System.out.printf("%02x ", (C >>> (i * 8)) & 0xFF);
        }

        for (int i = 0; i < loopSize; i++) {
            System.out.printf("%02x ", (D >>> (i * 8)) & 0xFF);
        }
    }
    private static void parseInput(String[] tokens){
        int i;
        int input;
        for (i = 0; i <Math.min(w_size / 8, tokens.length); i++) {
            input = Integer.parseInt(tokens[i], 16);
            A |= (input << (i * 8));
        }

        for (i = 0; i < Math.min(loopSize, tokens.length - loopSize); i++) {
            input = Integer.parseInt(tokens[i + (loopSize)], 16);
            B |= (input << (i * 8));
        }

        for (i = 0; i < (loopSize) && (i + 2 * (loopSize)) < tokens.length; i++) {
            input = Integer.parseInt(tokens[i + 2 * (loopSize)], 16);
            C |= (input << (i * 8));
        }

        for (i = 0; i < (w_size / 8) && (i + 3 * (w_size / 8)) < tokens.length; i++) {
            input = Integer.parseInt(tokens[i + 3 * (w_size / 8)], 16);
            D |= (input << (i * 8));
        }
    }

    public static void main(String[] args) throws IOException {
        int[] S_array = new int[size];
        int key_size = 0;  // Size of the key
        int L_size = 0;    // Size of L
        int key_bit = 0;   // Maximum key size is 256
        int CC;      // Value for CC
        int[] L_array = new int[9];  // Array for L, maximum used index is 8

        String inputText = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1";
        String userKey = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78";
        String keyword = "Encryption";

        // Read plaintext values
        String[] tokens = inputText.split(" ");
        parseInput(tokens);


        // Read userkey values
        tokens = userKey.split(" ");
        for (String token : tokens) {
            if (key_bit <= 256) {
                L_size = key_size / 4;
                int input = Integer.parseInt(token, 16);
                L_array[L_size] |= (input << (key_size % (loopSize) * 8));
                key_size++;
                key_bit += 8;
            }
        }

        CC = L_size + 1;

        // Key schedule
        S_array[0] = 0xB7E15163;            // Value of Magic constant P

        for (int i = 1; i < size; i++) {
            S_array[i] = S_array[i - 1] + 0x9E3779B9;               // Value of Magic constant Q
        }

        int key_A = 0;
        int key_B = 0;
        int key_i_value = 0;
        int key_j_value = 0;

        int v = 3 * Math.max(CC, size);
        for (int i = 1; i <= v; i++) {
            key_A = S_array[key_i_value] = leftShift((S_array[key_i_value] + key_A + key_B), 3);
            key_B = L_array[key_j_value] = leftShift((L_array[key_j_value] + key_A + key_B), (key_A + key_B));
            key_i_value = (key_i_value + 1) % (size);
            key_j_value = (key_j_value + 1) % (CC);
        }

        if(keyword.equalsIgnoreCase("Encryption")){
            encrypt(S_array);
        }else if(keyword.equalsIgnoreCase("Decryption")){
            decrypt(S_array);
        }

        printOutput();
    }
}

