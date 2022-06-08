package com.fjsimon.java.network.programming;

import java.io.IOException;
import java.io.OutputStream;

public class OutputStreamExample {


    public static void generateCharacters(OutputStream out) throws IOException {


        int firstPrintableCharacter = 33;
        int numberOfPrintableCharacters = 94;
        int numberOfCharactersPerLine = 72;
        int start = firstPrintableCharacter;
        int count = 0;

        do {
            for (int i = start; i < start + numberOfCharactersPerLine; i++) {
                out.write(((i - firstPrintableCharacter) % numberOfPrintableCharacters)
                        + firstPrintableCharacter);
            }

            out.write('\r'); // carriage return
            out.write('\n'); // linefeed

            start = ((start + 1) - firstPrintableCharacter) % numberOfPrintableCharacters
                    + firstPrintableCharacter;
            count++;
        } while (count <= numberOfPrintableCharacters);
    }

    public static void main(String...args) throws IOException {
        OutputStream outputStream = System.out;
        generateCharacters(outputStream);
    }
}
