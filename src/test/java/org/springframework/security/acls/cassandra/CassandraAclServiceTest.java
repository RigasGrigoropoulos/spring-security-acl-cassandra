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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import me.prettyprint.cassandra.service.ThriftKsDef;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.ddl.ColumnFamilyDefinition;
import me.prettyprint.hector.api.ddl.KeyspaceDefinition;
import me.prettyprint.hector.api.factory.HFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.ExpectedException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:/context.xml" })
public class CassandraAclServiceTest {

	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String ACL_CF = "AclColumnFamily";

	private static final String sid1 = "sid1@system";
	private static final String sid2 = "sid2@system";

	private static final String aoi_id = "123";
	private static final String aoi_class = "a.b.c.Class";
	private static final String ROLE_ADMIN = "ROLE_ADMIN";

	@Autowired
	private MutableAclService service;

	@Autowired
	private Cluster cluster;

	private KeyspaceDefinition keyspaceDef;

	@Before
	public void setUp() throws Exception {
		keyspaceDef = cluster.describeKeyspace(KEYSPACE);

		if (keyspaceDef != null) {
			cluster.dropColumnFamily(KEYSPACE, ACL_CF);
			cluster.dropKeyspace(KEYSPACE, true);
		}

		ColumnFamilyDefinition cfDef = HFactory.createColumnFamilyDefinition(KEYSPACE, ACL_CF);
		KeyspaceDefinition newKeyspace = HFactory.createKeyspaceDefinition(KEYSPACE, ThriftKsDef.DEF_STRATEGY_CLASS, 1, Arrays.asList(cfDef));
		// Add the schema to the cluster.
		// "true" as the second param means that Hector will block until all
		// nodes see the change.
		cluster.addKeyspace(newKeyspace, true);

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(sid1, "password", Arrays.asList(new SimpleGrantedAuthority[] { new SimpleGrantedAuthority(
						"ROLE_ADMIN") })));
		
	}

	@After
	public void tearDown() throws Exception {

	}

	private ObjectIdentity createDefaultTestOI() {
		ObjectIdentity oi = new ObjectIdentityImpl(aoi_class, aoi_id);
		return oi;
	}

	private void assertAcl(ObjectIdentity expected, Acl actual, String owner) {
		assertEquals(expected.getType(), actual.getObjectIdentity().getType());
		assertEquals(expected.getIdentifier(), actual.getObjectIdentity().getIdentifier());
		if (owner.startsWith("ROLE_")) {
			assertEquals(new GrantedAuthoritySid(owner), actual.getOwner());			
		} else {
			assertEquals(new PrincipalSid(owner), actual.getOwner());
		}		
	}
	
	private void assertAcl(Acl expected, Acl actual) {
		assertEquals(expected.getObjectIdentity().getType(), actual.getObjectIdentity().getType());
		assertEquals(expected.getObjectIdentity().getIdentifier(), actual.getObjectIdentity().getIdentifier());
		assertEquals(expected.getOwner(), actual.getOwner());		
		assertEquals(expected.isEntriesInheriting(), actual.isEntriesInheriting());		
		
		if (expected.getEntries() != null && actual.getEntries() != null) {
			assertEquals(expected.getEntries().size(), actual.getEntries().size());
			for (int i = 0; i < expected.getEntries().size(); i++) {
				assertAclEntry(expected.getEntries().get(i), actual.getEntries().get(i));
			}
		} else {
			assertEquals(expected.getEntries(), actual.getEntries());
		}
		
		if (expected.getParentAcl() != null && actual.getParentAcl() != null) {
			assertAcl(expected.getParentAcl(), actual.getParentAcl());
		} else {
			assertEquals(expected.getParentAcl(), actual.getParentAcl());
		}
	}

	private void assertAclEntry(AccessControlEntry expected, AccessControlEntry actual) {
		StringBuilder sb = new StringBuilder();
		sb.append(expected.getAcl().getObjectIdentity().getType()).append(":");
		sb.append(expected.getAcl().getObjectIdentity().getIdentifier()).append(":");
		
		if (expected.getSid() instanceof GrantedAuthoritySid) {
			sb.append(((GrantedAuthoritySid) expected.getSid()).getGrantedAuthority());
		} else if (expected.getSid() instanceof PrincipalSid) {
			sb.append(((PrincipalSid) expected.getSid()).getPrincipal());
		}
		
		assertEquals(sb.toString(), actual.getId());
		assertEquals(expected.getPermission(), actual.getPermission());
		assertEquals(expected.getSid(), actual.getSid());
		assertEquals(expected.isGranting(), actual.isGranting());
	}

	@Test
	public void testCreateFindUpdateDeleteAclWithParent() {
		// Test createAcl
		ObjectIdentity parentObjectIdentity = createDefaultTestOI();
		MutableAcl parentMutableAcl = service.createAcl(parentObjectIdentity);
		assertAcl(parentObjectIdentity, parentMutableAcl, sid1);

		// Test readAclById(ObjectIdentity)
		Acl parentAcl = service.readAclById(parentObjectIdentity);
		assertAcl(parentObjectIdentity, parentAcl, sid1);
		
		// Test updateAcl
		parentMutableAcl.setEntriesInheriting(true);
		parentMutableAcl.setOwner(new GrantedAuthoritySid(ROLE_ADMIN));
		MutableAcl updatedParentMutableAcl = service.updateAcl(parentMutableAcl);
		assertAcl(parentMutableAcl, updatedParentMutableAcl);

		// Test createAcl
		ObjectIdentity childObjectIdentity = new ObjectIdentityImpl(aoi_class, "567");
		MutableAcl childMutableAcl = service.createAcl(childObjectIdentity);
		assertAcl(childObjectIdentity, childMutableAcl, sid1);
		
		// Test updateAcl
		childMutableAcl.setParent(updatedParentMutableAcl);
		childMutableAcl.insertAce(0, BasePermission.READ, new PrincipalSid(sid1), true);
		childMutableAcl.insertAce(1, BasePermission.WRITE, new PrincipalSid(sid2), true);
		MutableAcl updatedchildMutableAcl = service.updateAcl(childMutableAcl);
		assertAcl(childMutableAcl, updatedchildMutableAcl);
		
		// Test readAclById(ObjectIdentity)
		Acl childAcl = service.readAclById(childObjectIdentity);
		assertAcl(updatedchildMutableAcl, childAcl);
		
		// Test readAclById(ObjectIdentity, List<Sid>) without Sid filter
		childAcl = service.readAclById(childObjectIdentity, null);
		assertAcl(updatedchildMutableAcl, childAcl);
		
		// Test readAclById(ObjectIdentity, List<Sid>) with all Sids in filter
		childAcl = service.readAclById(childObjectIdentity, Arrays.asList(new Sid[] { new PrincipalSid(sid1), new PrincipalSid(sid2) }));
		assertAcl(updatedchildMutableAcl, childAcl);
		
		// Test readAclById(ObjectIdentity, List<Sid>) with one Sid in filter
		childAcl = service.readAclById(childObjectIdentity, Arrays.asList(new Sid[] { new PrincipalSid(sid1) }));
		assertEquals(1, childAcl.getEntries().size());
		
		// Test readAclsById(List<ObjectIdentity>)
		Map<ObjectIdentity, Acl> resultMap = service.readAclsById(Arrays.asList(new ObjectIdentity[] { childObjectIdentity }));
		assertEquals(1, resultMap.size());
		assertAcl(updatedchildMutableAcl, resultMap.values().iterator().next());
		
		// Test readAclsById(List<ObjectIdentity>, List<Sid) without Sid filter
		resultMap = service.readAclsById(Arrays.asList(new ObjectIdentity[] { childObjectIdentity }), null);
		assertEquals(1, resultMap.size());
		assertAcl(updatedchildMutableAcl, resultMap.values().iterator().next());
		
		// Test readAclsById(List<ObjectIdentity>, List<Sid) with all Sids in filter
		resultMap = service.readAclsById(Arrays.asList(new ObjectIdentity[] { childObjectIdentity }), Arrays.asList(new Sid[] { new PrincipalSid(sid1), new PrincipalSid(sid2) }));
		assertEquals(1, resultMap.size());
		assertAcl(updatedchildMutableAcl, resultMap.values().iterator().next());
		
		// Test readAclsById(List<ObjectIdentity>, List<Sid) with one Sid in filter
		resultMap = service.readAclsById(Arrays.asList(new ObjectIdentity[] { childObjectIdentity }), Arrays.asList(new Sid[] { new PrincipalSid(sid1) }));
		assertEquals(1, resultMap.size());
		assertEquals(1, resultMap.values().iterator().next().getEntries().size());
		
		// Test deleteAcl 
		service.deleteAcl(childObjectIdentity, false);
		try {
			childAcl = service.readAclById(childObjectIdentity);
			fail("Expected NotFoundException");
		} catch (NotFoundException e) {
			// Expected exception
		}	
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testCreateNullAcl() {
		service.createAcl(null);
	}
	
	@Test
	@ExpectedException(AlreadyExistsException.class)
	public void testCreateAlreadyExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.createAcl(oi);
		service.createAcl(oi);		
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteNullAcl() {
		service.deleteAcl(null, false);
	}
	
	@Test
	public void testDeleteAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.deleteAcl(oi, false);	
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testUpdateNullAcl() {
		service.updateAcl(null);
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testUpdateAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		MutableAcl acl = service.createAcl(oi);
		service.deleteAcl(oi, false);	
		service.updateAcl(acl);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindChildrenNullAcl() {
		service.findChildren(null);
	}
	
	@Test
	public void testFindChildrenAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		List<ObjectIdentity> result = service.findChildren(oi);
		assertNull(result);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclByIdNullAcl() {
		service.readAclById(null);
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testReadAclByIdAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.readAclById(oi);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclByIdWithSidFilteringNullAcl() {
		service.readAclById(null, null);
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testReadAclByIdWithSidFilteringAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.readAclById(oi);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclsByIdNullAclList() {
		service.readAclsById(null);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclsByIdEmptyAclList() {
		service.readAclsById(new ArrayList<ObjectIdentity>());
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testReadAclsByIdAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.readAclsById(Arrays.asList(new ObjectIdentity[] { oi }));
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testReadAclsByIdOneAclNotExisting() {
		ObjectIdentity oi1 = createDefaultTestOI();
		service.createAcl(oi1);
		ObjectIdentity oi2 = new ObjectIdentityImpl(aoi_class, "invalid");
		service.readAclsById(Arrays.asList(new ObjectIdentity[] { oi1, oi2 }));
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclsByIdWithSidFilteringNullAclList() {
		service.readAclsById(null, null);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testReadAclsByIdWithSidFilteringEmptyAclList() {
		service.readAclsById(new ArrayList<ObjectIdentity>(), null);
	}
	
	@Test
	@ExpectedException(NotFoundException.class)
	public void testReadAclsByIdWithSidFilteringAclNotExisting() {
		ObjectIdentity oi = createDefaultTestOI();
		service.readAclsById(Arrays.asList(new ObjectIdentity[] { oi }), null);
	}

	
}
