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

import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;


public interface CassandraAclRepository {

	public Map<AclObjectIdentity, List<AclEntry>> findAcls(List<String> objectIdsToLookup, List<String> sids);

	public AclObjectIdentity findAclObjectIdentity(String objectId);
	
	public List<AclObjectIdentity> findAclObjectIdentityChildren(String objectId);

	public void deleteAcls(List<String> objectIdsToDelete);

	public void saveAcl(AclObjectIdentity aoi);	
	
	public void updateAcl(AclObjectIdentity aoi, List<AclEntry> entries);	

}
