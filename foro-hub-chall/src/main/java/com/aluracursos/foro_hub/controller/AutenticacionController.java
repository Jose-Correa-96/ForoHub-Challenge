package com.aluracursos.foro_hub.controller;

import com.aluracursos.foro_hub.infra.security.DatosJWTToken;
import com.aluracursos.foro_hub.infra.security.TokenService;
import com.aluracursos.foro_hub.domain.usuario.DatosAutenticacionUsuario;
import com.aluracursos.foro_hub.domain.usuario.Usuario;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
@Tag(name = "Autenticación", description = "Obtiene el token para el usuario asignado que da acceso al resto del endpoint")
public class AutenticacionController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    @PostMapping
    public ResponseEntity<DatosJWTToken> autenticarUsuario(@RequestBody @Valid DatosAutenticacionUsuario datosAutenticacionUsuario) {
        // Crear token de autenticación
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                datosAutenticacionUsuario.login(),
                datosAutenticacionUsuario.clave()
        );

        // Autenticar usuario
        var usuarioAutenticado = authenticationManager.authenticate(authToken);

        // Generar token JWT
        var JWTToken = tokenService.generarToken((Usuario) usuarioAutenticado.getPrincipal());

        // Devolver respuesta
        return ResponseEntity.ok(new DatosJWTToken(JWTToken));
    }
}
