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
package org.springframework.security.acls.cassandra;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.cassandra.repository.CassandraAclRepository;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.util.Assert;

public class CassandraMutableAclService extends CassandraAclService implements MutableAclService {

	private static final Log LOG = LogFactory.getLog(CassandraMutableAclService.class);

	public CassandraMutableAclService(CassandraAclRepository aclRepository, AclCache aclCache, PermissionGrantingStrategy grantingStrategy,
			AclAuthorizationStrategy aclAuthorizationStrategy) {
		super(aclRepository, aclCache, grantingStrategy, aclAuthorizationStrategy);
	}

	public MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
		Assert.notNull(objectIdentity, "Object Identity required");

		
		// TODO Auto-generated method stub
		return null;
	}

	public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {
		Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(objectIdentity.getIdentifier(), "Object Identity doesn't provide an identifier");
        
        List<ObjectIdentity> objectsToDelete = Arrays.asList(new ObjectIdentity[] { objectIdentity });
        
		if (deleteChildren) {
            List<ObjectIdentity> children = findChildren(objectIdentity);
            objectsToDelete.addAll(children);
		}
		
		// TODO Auto-generated method stub
		
		// Clear the cache
		if (aclCache != null) {
			for (ObjectIdentity obj : objectsToDelete) {
				aclCache.evictFromCache(obj);
			}
		}        
	}

	public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
		Assert.notNull(acl.getId(), "Object Identity doesn't provide an identifier");
		
		// TODO Auto-generated method stub
		
		// Clear the cache, including children
        clearCacheIncludingChildren(acl.getObjectIdentity());
		return null;
	}
	
	private void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
        Assert.notNull(objectIdentity, "ObjectIdentity required");
        List<ObjectIdentity> children = findChildren(objectIdentity);
        if (children != null) {
            for (ObjectIdentity child : children) {
                clearCacheIncludingChildren(child);
            }
        }
        
        if (aclCache != null) {
        	aclCache.evictFromCache(objectIdentity);
        }
    }

}
