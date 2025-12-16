package JsonWebToken.service;


import JsonWebToken.model.User;
import JsonWebToken.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private PasswordEncoder encoder;

    public void createUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));

    }
}
