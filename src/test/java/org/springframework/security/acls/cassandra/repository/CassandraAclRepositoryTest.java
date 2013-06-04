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
import java.util.List;
import java.util.Map;

import me.prettyprint.cassandra.serializers.CompositeSerializer;
import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.service.ThriftKsDef;
import me.prettyprint.cassandra.service.template.ColumnFamilyTemplate;
import me.prettyprint.cassandra.service.template.ThriftColumnFamilyTemplate;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.beans.Composite;
import me.prettyprint.hector.api.ddl.ColumnFamilyDefinition;
import me.prettyprint.hector.api.ddl.KeyspaceDefinition;
import me.prettyprint.hector.api.factory.HFactory;

import org.junit.After;
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
	private static final String sid2 = "sid2@system";
	
	private static final String aoi_id = "123";
	private static final String aoi_parent_id = "456";
	private static final String aoi_class = "a.b.c.Class";
	private static final String ROLE_ADMIN = "ROLE_ADMIN";

	@Autowired
	private CassandraAclRepository service;

	@Autowired
	private Cluster cluster;

	private ColumnFamilyTemplate<Composite, Composite> template;
	private Keyspace ksp;
	private KeyspaceDefinition keyspaceDef;

	@Before
	public void setUp() throws Exception {
		keyspaceDef = cluster.describeKeyspace(KEYSPACE);

		if (keyspaceDef != null) {
			cluster.dropColumnFamily(KEYSPACE, ACL_CF);
			cluster.dropKeyspace(KEYSPACE, true);
		}

		ColumnFamilyDefinition cfDef = HFactory.createColumnFamilyDefinition(KEYSPACE, ACL_CF);
		KeyspaceDefinition newKeyspace = HFactory.createKeyspaceDefinition(KEYSPACE, ThriftKsDef.DEF_STRATEGY_CLASS, 1,
				Arrays.asList(cfDef));
		// Add the schema to the cluster.
		// "true" as the second param means that Hector will block until all
		// nodes see the change.
		cluster.addKeyspace(newKeyspace, true);

		ksp = HFactory.createKeyspace(KEYSPACE, cluster);
		template = new ThriftColumnFamilyTemplate<Composite, Composite>(ksp, ACL_CF, CompositeSerializer.get(),
				CompositeSerializer.get());

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(sid1, "password", Arrays
						.asList(new SimpleGrantedAuthority[] { new SimpleGrantedAuthority("ROLE_ADMIN") })));
	}

	@After
	public void tearDown() throws Exception {

	}

	@Test
	public void testSaveFindUpdateDeleteAcl() {		
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId(aoi_id);
		newAoi.setEntriesInheriting(true);
		newAoi.setObjectClass(aoi_class);
		newAoi.setOwnerId(sid1);
		newAoi.setOwnerPrincipal(true);
		newAoi.setParentObjectId(aoi_parent_id);
		
		service.saveAcl(newAoi);
		
		AclObjectIdentity aoi = service.findAclObjectIdentity(newAoi);
		assertAclObjectIdentity(newAoi, aoi);		
		
		aoi.setEntriesInheriting(false);
		aoi.setParentObjectId(null);
		// Do not fill in id. It should get values automatically anyway.
		AclEntry entry1 = new AclEntry();
		entry1.setAuditFailure(true);
		entry1.setAuditSuccess(true);
		entry1.setGranting(true);
		entry1.setMask(1);
		entry1.setSid(sid1);
		entry1.setOrder(0);
		entry1.setSidPrincipal(true);
		
		AclEntry entry2 = new AclEntry();
		entry2.setAuditFailure(true);
		entry2.setAuditSuccess(true);
		entry2.setGranting(true);
		entry2.setMask(1);
		entry2.setSid(ROLE_ADMIN);
		entry2.setOrder(1);
		entry2.setSidPrincipal(false);
		
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
	public void testFindAclWithSidFiltering() {		
		fail("Not implemented yet");
	}
	
	@Test
	public void testFindAclList() {		
		fail("Not implemented yet");
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclListEmpty() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAclList() {	
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAcl() {
	}
	
	@Test
	public void testFindAclNotExisting() {		
		fail("Not implemented yet");
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclWithNullValues() {
	}
	
	@Test
	public void testFindAclChildren() {		
		fail("Not implemented yet");
	}
	
	@Test
	public void testFindAclChildrenForAclWithNoChildren() {		
		fail("Not implemented yet");
	}
	
	@Test
	public void testFindAclChildrenForNotExistingAcl() {		
		fail("Not implemented yet");
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindNullAclChildren() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testFindAclChildrenWithNullValues() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testUpdateNullAcl() {
	}
	
	@Test
	@ExpectedException(AclNotFoundException.class)
	public void testUpdateAclNotExisting() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testUpdateAclWithNullValues() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testSaveNullAcl() {		
		service.saveAcl(null);
	}
	
	@Test
	@ExpectedException(AclAlreadyExistsException.class)
	public void testSaveAclAlreadyExisting() {
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteNullAcl() {		
		service.deleteAcls(null);
	}
	
	@Test
	public void testDeleteAclNotExisting() {		
		fail("Not yet implemented");
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
		newAoi.setId(null);
		newAoi.setEntriesInheriting(true);
		newAoi.setObjectClass(null);
		newAoi.setOwnerId(null);
		newAoi.setOwnerPrincipal(true);
		newAoi.setParentObjectId(null);		
		service.saveAcl(newAoi);
	}
	
	@Test
	@ExpectedException(IllegalArgumentException.class)
	public void testDeleteAclWithNullValues() {	
		AclObjectIdentity newAoi = new AclObjectIdentity();
		newAoi.setId(null);
		newAoi.setEntriesInheriting(true);
		newAoi.setObjectClass(null);
		newAoi.setOwnerId(null);
		newAoi.setOwnerPrincipal(true);
		newAoi.setParentObjectId(null);
		service.deleteAcls(Arrays.asList(new AclObjectIdentity[] { newAoi }));
	}

	private void assertAclObjectIdentity(AclObjectIdentity expected, AclObjectIdentity actual) {
		assertEquals(expected.getId(), actual.getId());
		assertEquals(expected.getObjectClass(), actual.getObjectClass());
		assertEquals(expected.getOwnerId(), actual.getOwnerId());
		assertEquals(expected.getParentObjectId(), actual.getParentObjectId());
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
