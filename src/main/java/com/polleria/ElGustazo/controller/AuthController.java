package com.polleria.ElGustazo.controller;

import com.polleria.ElGustazo.dto.AuthRequest;
import com.polleria.ElGustazo.model.Usuario;
import com.polleria.ElGustazo.repository.UsuarioRepository;
import com.polleria.ElGustazo.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final UsuarioRepository usuarioRepository;

    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService,
                          JwtUtil jwtUtil,
                          UsuarioRepository usuarioRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
        this.usuarioRepository = usuarioRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o contraseña incorrectos");
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);
        Usuario usuario = usuarioRepository.findByUsername(authRequest.getUsername()).orElseThrow();

        return ResponseEntity.ok(new AuthResponse(jwt, usuario.getId(), usuario.getUsername(), usuario.getRol()));
    }
}

class AuthResponse {
    private String token;
    private Long id;
    private String username;
    private String rol;

    public AuthResponse(String token, Long id, String username, String rol) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.rol = rol;
    }

    public String getToken() { return token; }
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getRol() { return rol; }
}
