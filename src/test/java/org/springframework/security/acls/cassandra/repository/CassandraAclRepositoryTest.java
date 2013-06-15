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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import me.prettyprint.cassandra.service.ThriftKsDef;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.ddl.ColumnFamilyDefinition;
import me.prettyprint.hector.api.ddl.KeyspaceDefinition;
import me.prettyprint.hector.api.factory.HFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;
import org.springframework.security.acls.cassandra.repository.CassandraAclRepository;
import org.springframework.security.acls.cassandra.repository.exceptions.AclAlreadyExistsException;
import org.springframework.security.acls.cassandra.repository.exceptions.AclNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.ExpectedException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:/context.xml" })
public class CassandraAclRepositoryTest {

	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String ACL_CF = "AclColumnFamily";

	private static final String sid1 = "sid1@system";

	private static final String aoi_id = "123";
	private static final String aoi_parent_id = "456";
	private static final String aoi_class = "a.b.c.Class";
	private static final String ROLE_ADMIN = "ROLE_ADMIN";

	@Autowired
	private CassandraAclRepository service;

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
						ROLE_ADMIN) })));
	}

	@Test
	public void testSaveFindUpdateDeleteAcl() {
		AclObjectIdentity newAoi = createDefaultTestAOI();

		service.saveAcl(newAoi);

		AclObjectIdentity aoi = service.findAclObjectIdentity(newAoi);
		assertAclObjectIdentity(newAoi, aoi);

		aoi.setEntriesInheriting(false);
		// Do not fill in id. It should get values automatically anyway.
		AclEntry entry1 = createTestAclEntry(sid1, 0);
		AclEntry entry2 = createTestAclEntry(ROLE_ADMIN, 1);

		service.updateAcl(aoi, Arrays.asList(new AclEntry[] { entry1, entry2 }));

		Map<AclObjectIdentity, List<AclEntry>> result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { aoi }), null);
		assertEquals(1, result.size());
		assertAclObjectIdentity(aoi, result.keySet().iterator().next());
		List<AclEntry> aclEntries = result.values().iterator().next();
		assertAclEntry(aoi, entry1, aclEntries.get(1));
		assertAclEntry(aoi, entry2, aclEntries.get(0));

		service.deleteAcls(Arrays.asList(new AclObjectIdentity[] { aoi }));

		aoi = service.findAclObjectIdentity(aoi);
		assertNull(aoi);
	}

	@Test
	public void testFindAclListManyAclsWithSidFiltering() {
		AclObjectIdentity newAoi1 = createDefaultTestAOI();
		AclObjectIdentity newAoi2 = createDefaultTestAOI();
		newAoi2.setId("567");

		AclEntry entry1 = createTestAclEntry(sid1, 0);
		AclEntry entry2 = createTestAclEntry(ROLE_ADMIN, 1);

		service.saveAcl(newAoi1);
		service.saveAcl(newAoi2);
		service.updateAcl(newAoi1, Arrays.asList(new AclEntry[] { entry1, entry2 }));
		service.updateAcl(newAoi2, Arrays.asList(new AclEntry[] { entry1, entry2 }));

		Map<AclObjectIdentity, List<AclEntry>> result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { newAoi1, newAoi2 }),
				Arrays.asList(new String[] { ROLE_ADMIN }));
		
		assertEquals(2, result.size());
		Iterator<AclObjectIdentity> it = result.keySet().iterator();
		assertAclObjectIdentity(newAoi1, it.next());
		assertAclObjectIdentity(newAoi2, it.next());
		
		Iterator<List<AclEntry>> it2 = result.values().iterator();
		List<AclEntry> aclEntries = it2.next();
		assertEquals(1, aclEntries.size());
		assertAclEntry(newAoi1, entry2, aclEntries.get(0));
		aclEntries = it2.next();
		assertEquals(1, aclEntries.size());
		assertAclEntry(newAoi2, entry2, aclEntries.get(0));
	}

	@Test
	public void testFindAclListManyAcls() {
		AclObjectIdentity newAoi1 = createDefaultTestAOI();
		AclObjectIdentity newAoi2 = createDefaultTestAOI();
		newAoi2.setId("567");

		AclEntry entry1 = createTestAclEntry(sid1, 0);

		service.saveAcl(newAoi1);
		service.saveAcl(newAoi2);
		service.updateAcl(newAoi1, Arrays.asList(new AclEntry[] { entry1 }));
		service.updateAcl(newAoi2, Arrays.asList(new AclEntry[] { entry1 }));
		Map<AclObjectIdentity, List<AclEntry>> result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { newAoi1, newAoi2 }), null);
		
		assertEquals(2, result.size());
		Iterator<AclObjectIdentity> it = result.keySet().iterator();
		assertAclObjectIdentity(newAoi1, it.next());
		assertAclObjectIdentity(newAoi2, it.next());
		
		Iterator<List<AclEntry>> it2 = result.values().iterator();
		List<AclEntry> aclEntries = it2.next();
		assertEquals(1, aclEntries.size());
		assertAclEntry(newAoi1, entry1, aclEntries.get(0));
		aclEntries = it2.next();
		assertEquals(1, aclEntries.size());
		assertAclEntry(newAoi2, entry1, aclEntries.get(0));
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclListEmpty() {
		service.findAcls(new ArrayList<AclObjectIdentity>(), null);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAclList() {
		service.findAcls(null, null);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAcl() {
		service.findAclObjectIdentity(null);
	}

	@Test
	public void testFindAclNotExisting() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId("invalid");
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		service.findAclObjectIdentity(newAoi);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclWithNullValues() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		service.findAclObjectIdentity(newAoi);
	}

	@Test
	public void testFindAclChildren() {
		AclObjectIdentity newAoi1 = createDefaultTestAOI();
		service.saveAcl(newAoi1);
		
		AclObjectIdentity newAoi2 = createDefaultTestAOI();
		newAoi2.setId("456");
		newAoi2.setParentObjectClass(newAoi1.getObjectClass());
		newAoi2.setParentObjectId(newAoi1.getId());
		service.saveAcl(newAoi2);
		
		List<AclObjectIdentity> children = service.findAclObjectIdentityChildren(newAoi1);
		assertNotNull(children);
		assertEquals(1, children.size());
		assertEquals(newAoi2.getId(), children.get(0).getId());
		assertEquals(newAoi2.getObjectClass(), children.get(0).getObjectClass());
	}

	@Test
	public void testFindAclChildrenForAclWithNoChildren() {
		AclObjectIdentity newAoi1 = createDefaultTestAOI();
		service.saveAcl(newAoi1);
		List<AclObjectIdentity> children = service.findAclObjectIdentityChildren(newAoi1);
		assertNull(children);
	}

	@Test
	public void testFindAclChildrenForNotExistingAcl() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId("invalid");
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		List<AclObjectIdentity> children = service.findAclObjectIdentityChildren(newAoi);
		assertNull(children);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAclChildren() {
		service.findAclObjectIdentityChildren(null);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclChildrenWithNullValues() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		service.findAclObjectIdentityChildren(newAoi);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testUpdateNullAcl() {
		service.updateAcl(null, null);
	}

	@Test
	public void testUpdateAclNullEntries() {
		AclObjectIdentity newAoi = createDefaultTestAOI();
		service.saveAcl(newAoi);

		AclEntry entry1 = createTestAclEntry(sid1, 0);
		service.updateAcl(newAoi, Arrays.asList(new AclEntry[] { entry1 }));

		Map<AclObjectIdentity, List<AclEntry>> result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { newAoi }), null);
		assertEquals(1, result.size());
		assertAclObjectIdentity(newAoi, result.keySet().iterator().next());
		List<AclEntry> aclEntries = result.values().iterator().next();
		assertAclEntry(newAoi, entry1, aclEntries.get(0));

		service.updateAcl(newAoi, null);
		result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { newAoi }), null);
		assertEquals(1, result.size());
		assertAclObjectIdentity(newAoi, result.keySet().iterator().next());
		assertTrue(result.values().iterator().next().isEmpty());
	}

	@Test
	@ExpectedException(AclNotFoundException.class)
	public void testUpdateAclNotExisting() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId("invalid");
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		service.updateAcl(newAoi, new ArrayList<AclEntry>());
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testSaveNullAcl() {
		service.saveAcl(null);
	}

	@Test
	@ExpectedException(AclAlreadyExistsException.class)
	public void testSaveAclAlreadyExisting() {
		AclObjectIdentity newAoi = createDefaultTestAOI();
		service.saveAcl(newAoi);
		service.saveAcl(newAoi);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteNullAcl() {
		service.deleteAcls(null);
	}

	@Test
	public void testDeleteAclNotExisting() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId("invalid");
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		service.deleteAcls(Arrays.asList(new AclObjectIdentity[] { newAoi }));
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteEmptyAclList() {
		service.deleteAcls(new ArrayList<AclObjectIdentity>());
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testSaveAclWithNullValues() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		service.saveAcl(newAoi);
	}

	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteAclWithNullValues() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		service.deleteAcls(Arrays.asList(new AclObjectIdentity[] { newAoi }));
	}

	private AclEntry createTestAclEntry(String sid, int order) {
		AclEntry entry1 = new AclEntry();
		entry1.setAuditFailure(true);
		entry1.setAuditSuccess(true);
		entry1.setGranting(true);
		entry1.setMask(1);
		entry1.setSid(sid);
		entry1.setOrder(order);
		if (sid.startsWith("ROLE_")) {
			entry1.setSidPrincipal(false);
		} else {
			entry1.setSidPrincipal(true);
		}		
		return entry1;
	}

	private AclObjectIdentity createDefaultTestAOI() {
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId(aoi_id);
		newAoi.setEntriesInheriting(true);
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		newAoi.setOwnerPrincipal(true);
		newAoi.setParentObjectId(aoi_parent_id);
		newAoi.setParentObjectClass(aoi_class);
		return newAoi;
	}

	private void assertAclObjectIdentity(AclObjectIdentity expected, AclObjectIdentity actual) {
		assertEquals(expected.getId(), actual.getId());
		assertEquals(expected.getObjectClass(), actual.getObjectClass());
		assertEquals(expected.getOwnerId(), actual.getOwnerId());
		assertEquals(expected.getParentObjectId(), actual.getParentObjectId());
		assertEquals(expected.getParentObjectClass(), actual.getParentObjectClass());
		assertEquals(expected.isEntriesInheriting(), actual.isEntriesInheriting());
		assertEquals(expected.isOwnerPrincipal(), actual.isOwnerPrincipal());
	}

	private void assertAclEntry(AclObjectIdentity expectedOi, AclEntry expected, AclEntry actual) {
		assertEquals(expectedOi.getObjectClass() + ":" + expectedOi.getId() + ":" + expected.getSid(), actual.getId());
		assertEquals(expected.getMask(), actual.getMask());
		assertEquals(expected.getOrder(), actual.getOrder());
		assertEquals(expected.getSid(), actual.getSid());
		assertEquals(expected.isAuditFailure(), actual.isAuditFailure());
		assertEquals(expected.isAuditSuccess(), actual.isAuditSuccess());
		assertEquals(expected.isGranting(), actual.isGranting());
		assertEquals(expected.isSidPrincipal(), actual.isSidPrincipal());
	}

}
