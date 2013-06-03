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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;
import org.springframework.security.acls.cassandra.repository.CassandraAclRepository;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public class CassandraMutableAclService extends CassandraAclService implements MutableAclService {

	private static final Log LOG = LogFactory.getLog(CassandraMutableAclService.class);

	public CassandraMutableAclService(CassandraAclRepository aclRepository, AclCache aclCache,
			PermissionGrantingStrategy grantingStrategy, AclAuthorizationStrategy aclAuthorizationStrategy) {
		super(aclRepository, aclCache, grantingStrategy, aclAuthorizationStrategy);
	}

	public MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN createAcl: objectIdentity: " + objectIdentity);
		}
		Assert.notNull(objectIdentity, "Object Identity required");

		// Check this object identity hasn't already been persisted
		if (aclRepository.findAclObjectIdentity((String) objectIdentity.getIdentifier()) != null) {
			throw new AlreadyExistsException("Object identity '" + objectIdentity + "' already exists");
		}

		// Need to retrieve the current principal, in order to know who "owns"
		// this ACL (can be changed later on)
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		PrincipalSid sid = new PrincipalSid(auth);

		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setOwnerId(sid.getPrincipal());
		newAoi.setOwnerPrincipal(true);
		newAoi.setObjectClass(objectIdentity.getType());
		newAoi.setId((String) objectIdentity.getIdentifier());
		aclRepository.saveAcl(newAoi);

		// Retrieve the ACL via superclass (ensures cache registration, proper
		// retrieval etc)
		Acl acl = readAclById(objectIdentity);
		Assert.isInstanceOf(MutableAcl.class, acl, "MutableAcl should be been returned");

		if (LOG.isDebugEnabled()) {
			LOG.debug("END createAcl: acl: " + acl);
		}
		return (MutableAcl) acl;
	}

	public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN deleteAcl: objectIdentity: " + objectIdentity + ", deleteChildren: " + deleteChildren);
		}
		Assert.notNull(objectIdentity, "Object Identity required");
		Assert.notNull(objectIdentity.getIdentifier(), "Object Identity doesn't provide an identifier");

		List<ObjectIdentity> objectsToDelete = Arrays.asList(new ObjectIdentity[] { objectIdentity });
		List<String> objIdsToDelete = new ArrayList<String>();

		List<ObjectIdentity> children = findChildren(objectIdentity);
		if (deleteChildren) {
			while (children != null) {
				objectsToDelete.addAll(children);
				children = findChildren(objectIdentity);
			}			
		} else if (children != null && !children.isEmpty()) {
			throw new ChildrenExistException("Cannot delete '" + objectIdentity + "' (has " + children.size()
					+ " children)");
		}

		for (ObjectIdentity objId : objectsToDelete) {
			objIdsToDelete.add((String) objId.getIdentifier());
		}
		aclRepository.deleteAcls(objIdsToDelete);

		// Clear the cache
		if (aclCache != null) {
			for (ObjectIdentity obj : objectsToDelete) {
				aclCache.evictFromCache(obj);
			}
		}
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END deleteAcl");
		}
	}

	public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN updateAcl: acl: " + acl);
		}
		Assert.notNull(acl.getId(), "Object Identity doesn't provide an identifier");

		// Check this object identity is already persisted
		if (aclRepository.findAclObjectIdentity((String) acl.getId()) == null) {
			throw new NotFoundException("Object identity '" + (String) acl.getId() + "' does not exist");
		}

		aclRepository.updateAcl(convertToAclObjectIdentity(acl), convertToAclEntries(acl));

		// Clear the cache, including children
		clearCacheIncludingChildren(acl.getObjectIdentity());
		
		// Retrieve the ACL via superclass (ensures cache registration, proper
		// retrieval etc)
		MutableAcl result = (MutableAcl) readAclById(acl.getObjectIdentity());
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END updateAcl: acl: " + result);
		}
		return result;
	}

	private List<AclEntry> convertToAclEntries(Acl acl) {
		List<AclEntry> result = new ArrayList<AclEntry>();
		
		for (int i = 0; i < acl.getEntries().size(); i++ ) {
			AccessControlEntry entry = acl.getEntries().get(i);
			AclEntry ae = new AclEntry();
			ae.setGranting(entry.isGranting());
			ae.setId((String) entry.getId());
			ae.setMask(entry.getPermission().getMask());
			ae.setObjectIdentity((String) acl.getObjectIdentity().getIdentifier());
			ae.setOrder(i);
			
			if (acl.getOwner() instanceof PrincipalSid) {
				ae.setSid(((PrincipalSid) entry.getSid()).getPrincipal());
				ae.setSidPrincipal(true);
			} else if (acl.getOwner() instanceof GrantedAuthoritySid) {
				ae.setSid(((GrantedAuthoritySid)entry.getSid()).getGrantedAuthority());
				ae.setSidPrincipal(false);
			}
			
			if (entry instanceof AuditableAccessControlEntry) {
				ae.setAuditFailure(((AuditableAccessControlEntry) entry).isAuditFailure());
				ae.setAuditSuccess(((AuditableAccessControlEntry) entry).isAuditSuccess());
			} else {
				ae.setAuditFailure(false);
				ae.setAuditSuccess(false);
			}
			
			result.add(ae);
		}
		
		return result;
	}

	private AclObjectIdentity convertToAclObjectIdentity(Acl acl) {
		AclObjectIdentity result = new AclObjectIdentity();
		result.setEntriesInheriting(acl.isEntriesInheriting());
		result.setId((String) acl.getObjectIdentity().getIdentifier());
		result.setObjectClass(acl.getObjectIdentity().getType());
		if (acl.getOwner() instanceof PrincipalSid) {
			result.setOwnerId(((PrincipalSid) acl.getOwner()).getPrincipal());
			result.setOwnerPrincipal(true);
		} else if (acl.getOwner() instanceof GrantedAuthoritySid) {
			result.setOwnerId(((GrantedAuthoritySid) acl.getOwner()).getGrantedAuthority());
			result.setOwnerPrincipal(false);
		}
		result.setParentObjectId((String) acl.getParentAcl().getObjectIdentity().getIdentifier());

		return result;
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
