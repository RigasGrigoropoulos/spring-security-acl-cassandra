/* Copyright 2013 Rigas Grigoropoulos
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.cassandra.repository;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;
import org.springframework.security.acls.cassandra.repository.exceptions.AclAlreadyExistsException;
import org.springframework.security.acls.cassandra.repository.exceptions.AclNotFoundException;


/**
 * @author Rigas Grigoropoulos
 *
 */
public interface CassandraAclRepository {

	/**
	 * @param objectIdsToLookup
	 * @return
	 */
	Map<AclObjectIdentity, Set<AclEntry>> findAcls(List<AclObjectIdentity> objectIdsToLookup);

	/**
	 * @param objectId
	 * @return
	 */
	AclObjectIdentity findAclObjectIdentity(AclObjectIdentity objectId);
	
	/**
	 * @param objectId
	 * @return
	 */
	List<AclObjectIdentity> findAclObjectIdentityChildren(AclObjectIdentity objectId);

	/**
	 * @param objectIdsToDelete
	 */
	void deleteAcls(List<AclObjectIdentity> objectIdsToDelete);

	/**
	 * @param aoi
	 * @throws AclAlreadyExistsException
	 */
	void saveAcl(AclObjectIdentity aoi) throws AclAlreadyExistsException;	
	
	/**
	 * @param aoi
	 * @param entries
	 * @throws AclNotFoundException
	 */
	void updateAcl(AclObjectIdentity aoi, List<AclEntry> entries) throws AclNotFoundException;	

}
