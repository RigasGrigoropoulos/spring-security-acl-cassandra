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

import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.service.ThriftKsDef;
import me.prettyprint.cassandra.service.template.ColumnFamilyTemplate;
import me.prettyprint.cassandra.service.template.ColumnFamilyUpdater;
import me.prettyprint.cassandra.service.template.ThriftColumnFamilyTemplate;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.ddl.ColumnFamilyDefinition;
import me.prettyprint.hector.api.ddl.KeyspaceDefinition;
import me.prettyprint.hector.api.factory.HFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:/context.xml"})
public class CassandraAclServiceTest {
	
	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String ACL_CF = "AclColumnFamily";
	
	private static final String COLUMN_NAME_TOKEN_SEPERATOR = "_:_";
	
	private static final String objectClass = "objectClass";
	private static final String parentObjectId = "parentObjectId";
	private static final String ownerSid = "ownerSid";
	private static final String ownerIsPrincipal = "ownerIsPrincipal";
	private static final String entriesInheriting = "entriesInheriting";
	private static final String aceOrder = "aceOrder";
	private static final String sidIsPrincipal = "sidIsPrincipal";
	private static final String granting = "granting";
	private static final String mask = "mask";
	private static final String auditSuccess = "auditSuccess";
	private static final String auditFailure = "auditFailure";
	
	private static final String sid1 = "sid1";
	private static final String sid2 = "sid2";
	
	private static final String objectIdentity = AclEntry.class.getName() + COLUMN_NAME_TOKEN_SEPERATOR + "123";
	
	@Autowired
	private AclService service;
	
	@Autowired
	private Cluster cluster;
	
	private ColumnFamilyTemplate<String, String> template;
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
		template = new ThriftColumnFamilyTemplate<String, String>(ksp, ACL_CF, StringSerializer.get(), StringSerializer.get());	
				
		addAclForObject(objectIdentity);
		addAceForSid(sid1, objectIdentity);
	}

	@After
	public void tearDown() throws Exception {		
		
	}

	@Test
	public void testReadAclById() {
		Acl acl = service.readAclById(new ObjectIdentityImpl(AclEntry.class.getName(), objectIdentity));
		assertEquals(new PrincipalSid(sid1), acl.getOwner());
		assertEquals(false, acl.isEntriesInheriting());
		assertEquals(null, acl.getParentAcl());
		assertEquals(objectIdentity, acl.getObjectIdentity().getIdentifier());
		assertEquals(AclEntry.class.getName(), acl.getObjectIdentity().getType());
		assertEquals(acl, acl.getEntries().get(0).getAcl());
		assertEquals(objectIdentity + COLUMN_NAME_TOKEN_SEPERATOR + sid1, acl.getEntries().get(0).getId());
		assertEquals(true, acl.getEntries().get(0).isGranting());
		assertEquals(1, acl.getEntries().get(0).getPermission().getMask());
		assertEquals(false, ((AccessControlEntryImpl) acl.getEntries().get(0)).isAuditFailure());
		assertEquals(false, ((AccessControlEntryImpl) acl.getEntries().get(0)).isAuditSuccess());
		assertEquals(new PrincipalSid(sid1), ((AccessControlEntryImpl) acl.getEntries().get(0)).getSid());
	}
	
	private void addAceForSid(String sid, String objectId) {
		ColumnFamilyUpdater<String, String> updater = template.createUpdater(objectId);
		updater.setInteger(sid + COLUMN_NAME_TOKEN_SEPERATOR + aceOrder, 1);
		updater.setInteger(sid + COLUMN_NAME_TOKEN_SEPERATOR + mask, 1);
		updater.setBoolean(sid + COLUMN_NAME_TOKEN_SEPERATOR + auditSuccess, false);
		updater.setBoolean(sid + COLUMN_NAME_TOKEN_SEPERATOR + auditFailure, false);
		updater.setBoolean(sid + COLUMN_NAME_TOKEN_SEPERATOR + sidIsPrincipal, true);
		updater.setBoolean(sid + COLUMN_NAME_TOKEN_SEPERATOR + granting, true);
		template.update(updater);
	}
	
	private void addAclForObject(String objectId) {
		ColumnFamilyUpdater<String, String> updater = template.createUpdater(objectId);
		updater.setString(objectClass, AclEntry.class.getName());
		updater.setString(parentObjectId, "");
		updater.setString(ownerSid, sid1);
		updater.setBoolean(ownerIsPrincipal, true);
		updater.setBoolean(entriesInheriting, false);
		template.update(updater);
	}

}
