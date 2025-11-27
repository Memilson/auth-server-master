package info.datahorizons.authserver.persistence;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import info.datahorizons.authserver.model.UserAuth;

@Repository
public interface UserAuthDao extends CrudRepository<UserAuth, String>{

	UserAuth findByLoginAndActiveTrue(String login);
	
}
