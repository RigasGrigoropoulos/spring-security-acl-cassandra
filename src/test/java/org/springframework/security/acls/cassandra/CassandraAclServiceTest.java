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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import me.prettyprint.cassandra.serializers.CompositeSerializer;
import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.service.ThriftKsDef;
import me.prettyprint.cassandra.service.template.ColumnFamilyTemplate;
import me.prettyprint.cassandra.service.template.ColumnFamilyUpdater;
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
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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
	private static final String aoi_parent_id = "456";
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
		ObjectIdentity parentObjectIdentity = createDefaultTestOI();
		MutableAcl parentMutableAcl = service.createAcl(parentObjectIdentity);
		assertAcl(parentObjectIdentity, parentMutableAcl, sid1);

		Acl parentAcl = service.readAclById(parentObjectIdentity);
		assertAcl(parentObjectIdentity, parentAcl, sid1);
		
		parentMutableAcl.setEntriesInheriting(true);
		parentMutableAcl.setOwner(new GrantedAuthoritySid(ROLE_ADMIN));
		MutableAcl updatedParentMutableAcl = service.updateAcl(parentMutableAcl);
		assertAcl(parentMutableAcl, updatedParentMutableAcl);

		ObjectIdentity childObjectIdentity = new ObjectIdentityImpl(aoi_class, "567");
		MutableAcl childMutableAcl = service.createAcl(childObjectIdentity);
		assertAcl(childObjectIdentity, childMutableAcl, sid1);
		
		childMutableAcl.setParent(updatedParentMutableAcl);
		childMutableAcl.insertAce(0, BasePermission.READ, new PrincipalSid(sid1), true);
		childMutableAcl.insertAce(1, BasePermission.WRITE, new PrincipalSid(sid2), true);
		MutableAcl updatedchildMutableAcl = service.updateAcl(childMutableAcl);
		assertAcl(childMutableAcl, updatedchildMutableAcl);
		
//
//		Map<AclObjectIdentity, List<AclEntry>> result = service.findAcls(Arrays.asList(new AclObjectIdentity[] { aoi }), null);
//		assertEquals(1, result.size());
//		assertAclObjectIdentity(aoi, result.keySet().iterator().next());
//		List<AclEntry> aclEntries = result.values().iterator().next();
//		assertAclEntry(aoi, entry1, aclEntries.get(1));
//		assertAclEntry(aoi, entry2, aclEntries.get(0));
//
//		service.deleteAcls(Arrays.asList(new AclObjectIdentity[] { aoi }));
//
//		aoi = service.findAclObjectIdentity(aoi);
//		assertNull(aoi);
	}

}
