package org.springframework.security.acls.cassandra.repository;

import java.util.List;
import java.util.Map;

import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;


public interface CassandraAclRepository {

	Map<AclObjectIdentity, List<AclEntry>> findAclEntries(List<String> objectIdsToLookup, List<String> sids);

	
	

}
