package fileio;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Input {
    private String version;
    private String schema;
    private Scan scanner;
    private List<Vulnerability> vulnerabilities;

    //@JsonProperty("dependency_files")
    private List<DependencyFile> dependencyFiles;
}
