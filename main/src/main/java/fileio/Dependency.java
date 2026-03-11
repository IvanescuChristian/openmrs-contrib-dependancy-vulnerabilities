package fileio;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Dependency {
    @JsonProperty("package")
    private PackageDetails packageDetails;

    private String version;
}
