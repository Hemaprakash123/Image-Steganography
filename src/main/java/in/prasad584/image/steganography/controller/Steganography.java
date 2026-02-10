package in.prasad584.image.steganography.controller;


import in.prasad584.image.steganography.service.StegoService;
import org.springframework.http.*;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.Map;

@RestController
@Validated
@RequestMapping("/api/v1")
@CrossOrigin(origins = "${app.frontend.url}",allowCredentials = "true")
public class Steganography {


    public Steganography(StegoService stegoService) {
        this.stegoService = stegoService;
    }

    private final StegoService stegoService;

    @PostMapping(value = "encode", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> encode(@RequestPart("image") MultipartFile image,
                                         @RequestPart("message") String message,
                                         @RequestPart(value = "password", required = false) String password) throws Exception {
        byte[] stego = stegoService.embedMessage(image.getBytes(), message, password);
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.IMAGE_PNG);
        h.setContentDisposition(ContentDisposition.attachment().filename("stego.png").build());
        return new ResponseEntity<>(stego, h, HttpStatus.OK);
    }

    @PostMapping(value = "decode", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String,String>> decode(@RequestPart("image") MultipartFile image,
                                                     @RequestPart(value = "password", required = false) String password) throws Exception {
        String msg = stegoService.extractMessage(image.getBytes(), password);
        return ResponseEntity.ok(Map.of("message", msg));
    }

}
