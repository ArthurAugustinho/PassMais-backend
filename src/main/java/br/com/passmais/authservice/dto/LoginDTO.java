package br.com.passmais.authservice.dto;

import lombok.Data;

@Data
public class LoginDTO {
    private String email;
    private String password;
}
