/**
 * A helper file to write lines of code to a CSV file
 */

package com.matoalot.authsim.Logger;
import java.io.FileWriter;
import java.io.IOException;

public class CsvWriter {
    /**
     * A function that writes a line to a CSV file
     * @param writer
     * @param fields
     * @throws IOException
     */
    public static void writeLine(FileWriter writer, String ... fields)throws IOException{
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<fields.length; i++){
            sb.append(fields[i].replace(",",";"));
            if(i < fields.length-1){
                sb.append(",");
            }
            sb.append("\n");
            writer.write(sb.toString());
        }
    }
}
