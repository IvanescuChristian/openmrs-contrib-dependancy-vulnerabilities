package org.example;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import fileio.Input;
import fileio.Vulnerability;

import java.io.File;
import java.io.IOException;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Input inputData = mapper.readValue(new File("report.json"), Input.class);
        String firstVulnName = inputData.getVulnerabilities().get(0).getName();
        String packageName = inputData.getVulnerabilities().get(0)
                .getLocation().getDependency()
                .getPackageDetails().getName();
        for  (Vulnerability vuln : inputData.getVulnerabilities()) {

        }
    }
}