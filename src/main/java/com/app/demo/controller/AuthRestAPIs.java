package com.app.demo.controller;

import com.app.demo.message.request.LoginForm;
import com.app.demo.message.request.SignUpForm;
import com.app.demo.message.response.JwtResponse;
import com.app.demo.message.response.ResponseMessage;
import com.app.demo.model.Role;
import com.app.demo.model.RoleName;
import com.app.demo.model.User;
import com.app.demo.repository.RoleRepository;
import com.app.demo.repository.UserRepository;
import com.app.demo.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {
        checkIfUserExistsByUserName(signUpRequest.getUsername());
        checkIfUserExistsByEmail(signUpRequest.getEmail());

        // Creating user's account
        User user = new User(signUpRequest.getFirstname(), signUpRequest.getLastname(), signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()), signUpRequest.getAddress());

        Set<Role> roles;
        roles = associateRolesToUser(signUpRequest.getRole());
        user.setRoles(roles);
        userRepository.save(user);

        return new ResponseEntity<>(new ResponseMessage("User registered successfully!"), HttpStatus.OK);
    }

    @GetMapping(value = "/searchby")
    public ResponseEntity<?> SearchByCriteria(@RequestParam(required = false) Map<String, String> map) {
        String mail = map.get("mail");
        String username = map.get("username");
        Optional<User> user;
        try {
            if (mail != null) {
                user = this.userRepository.findByEmail(mail);
                if (user.isPresent()) {

                    return new ResponseEntity<>(new ResponseMessage(String.valueOf(user.get().getEmail())), HttpStatus.OK);
                }
            }
            if (username != null) {
                user = this.userRepository.findByUsername(username);
                if (user.isPresent()) {
                    return new ResponseEntity<>(new ResponseMessage(String.valueOf(user.get().getUsername())), HttpStatus.OK);

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private Set<Role> associateRolesToUser(Set<String> roles) {
        Set<Role> setOfRoles = new HashSet<>();

        roles.forEach(role -> {
            System.out.println(role);
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: Admin Role not find."));
                    setOfRoles.add(adminRole);

                    break;
                case "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: Pm Role not find."));
                    setOfRoles.add(pmRole);

                    break;
                case "user":
                    Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                    setOfRoles.add(userRole);
                default:
                    throw new RuntimeException("Fail ! -> Cause : the type" + role + "is not valid");
            }
        });
        return setOfRoles;
    }

    private ResponseEntity<?> checkIfUserExistsByUserName(String userName) {
        if (userRepository.existsByUsername(userName)) {
            return new ResponseEntity<>(new ResponseMessage("Fail -> Username is already taken!"),
                    HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(new ResponseMessage("Success -> Username is Free!"),
                HttpStatus.OK);
    }

    private ResponseEntity<?> checkIfUserExistsByEmail(String email) {
        if (userRepository.existsByUsername(email)) {
            return new ResponseEntity<>(new ResponseMessage("Fail -> Email is already taken!"),
                    HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(new ResponseMessage("Success -> Email is Free!"),
                HttpStatus.OK);
    }

}