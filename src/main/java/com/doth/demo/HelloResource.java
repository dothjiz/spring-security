package com.doth.demo;

import com.doth.demo.models.AuthenticationRequest;
import com.doth.demo.models.AuthenticationResponse;
import com.doth.demo.security.CustomUserDetailService;
import com.doth.demo.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class HelloResource {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailService userDetailService;
    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping(value = "/he", method = RequestMethod.GET)
    public String hello(){
        return "Hello World";
    }

    @RequestMapping(value="/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) throws Exception{
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        }catch (BadCredentialsException e){
            throw new Exception("Incorrect username or password, e");
        }
        final UserDetails userDetails = userDetailService.loadUserByUsername(request.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

}
