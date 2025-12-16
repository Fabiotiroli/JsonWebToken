package JsonWebToken.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.userdetails.User;


    public interface UserRepository extends JpaRepository<User, Integer> {
        JsonWebToken.model.User findByUsername(String username);


    @Query("SELECT e FROM User e JOIN FETCH e.roles WHERE e.username= (:username)")
    public User findByUsernamex(@Param("username") String username);

    public User savePassword(JsonWebToken.model.User user);


    boolean existsByUsername(String username);



}
