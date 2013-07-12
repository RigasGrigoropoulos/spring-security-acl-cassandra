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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;
import org.springframework.security.acls.cassandra.repository.exceptions.AclAlreadyExistsException;
import org.springframework.security.acls.cassandra.repository.exceptions.AclNotFoundException;
import org.springframework.util.Assert;

import com.datastax.driver.core.BoundStatement;
import com.datastax.driver.core.PreparedStatement;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.exceptions.AlreadyExistsException;
import com.datastax.driver.core.querybuilder.QueryBuilder;

public class CassandraAclRepositoryImpl implements CassandraAclRepository {

	private static final Log LOG = LogFactory.getLog(CassandraAclRepositoryImpl.class);

	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String AOI_TABLE = "aois";
	private static final String CHILDREN_TABLE = "children";
	private static final String ACL_TABLE = "acls";
	private static final String INSERT_AOI = "INSERT INTO " + KEYSPACE + "." + AOI_TABLE
			+ " (id, objId, objClass, isInheriting, owner, isOwnerPrincipal, parentObjId, parentObjClass) " 
			+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
	private static final String INSERT_CHILD = "INSERT INTO " + KEYSPACE + "." + CHILDREN_TABLE
			+ " (id, childId, objId, objClass) " 
			+ "VALUES (?, ?, ?, ?);";
	private static final String INSERT_ACL = "INSERT INTO " + KEYSPACE + "." + ACL_TABLE
			+ " (id, aclOrder, sid, mask, isSidPrincipal, isGranting, isAuditSuccess, isAuditFailure) " 
			+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

	private final PreparedStatement insertAoiStatement;
	private final PreparedStatement insertChildStatement;
	private final PreparedStatement insertAclStatement;

	private Session session;

	public CassandraAclRepositoryImpl(Session session) {
		this.session = session;
		insertAoiStatement = session.prepare(INSERT_AOI);
		insertChildStatement = session.prepare(INSERT_CHILD);
		insertAclStatement = session.prepare(INSERT_ACL);
	}
	
	public CassandraAclRepositoryImpl(Session session, boolean initSchema) {
		this.session = session;
		if (initSchema) {
			createKeyspace();
			createAoisTable();
			createChilrenTable();
			createAclsTable();
		}
		insertAoiStatement = session.prepare(INSERT_AOI);
		insertChildStatement = session.prepare(INSERT_CHILD);
		insertAclStatement = session.prepare(INSERT_ACL);
	}

	public Map<AclObjectIdentity, Set<AclEntry>> findAcls(List<AclObjectIdentity> objectIdsToLookup) {
		assertAclObjectIdentityList(objectIdsToLookup);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAcls: objectIdentities: " + objectIdsToLookup);
		}
		Map<AclObjectIdentity, Set<AclEntry>> resultMap = new HashMap<AclObjectIdentity, Set<AclEntry>>();		

		List<String> ids = new ArrayList<String>();
		for (AclObjectIdentity entry : objectIdsToLookup) {
			ids.add(entry.getRowId());
		}
		
		ResultSet resultSet = session.execute(QueryBuilder.select().all().from(KEYSPACE, AOI_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		for (Row row : resultSet.all()) {
			resultMap.put(convertToAclObjectIdentity(row, true), new TreeSet<AclEntry>(new Comparator<AclEntry>() {

				public int compare(AclEntry o1, AclEntry o2) {
					return Integer.compare(o1.getOrder(), o2.getOrder());
				}
			}));
		}
		
		resultSet = session.execute(QueryBuilder.select().all().from(KEYSPACE, ACL_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		for (Row row : resultSet.all()) {
			String aoiId = row.getString("id");
			
			AclEntry aclEntry = new AclEntry();
			aclEntry.setAuditFailure(row.getBool("isAuditFailure"));
			aclEntry.setAuditSuccess(row.getBool("isAuditSuccess"));
			aclEntry.setGranting(row.getBool("isGranting"));
			aclEntry.setMask(row.getInt("mask"));
			aclEntry.setOrder(row.getInt("aclOrder"));
			aclEntry.setSid(row.getString("sid"));
			aclEntry.setSidPrincipal(row.getBool("isSidPrincipal"));			
			aclEntry.setId(aoiId + ":" + aclEntry.getSid() + ":" + aclEntry.getOrder());
			
			for (Entry<AclObjectIdentity, Set<AclEntry>> entry : resultMap.entrySet()) {
				if (entry.getKey().getRowId().equals(aoiId)) {
					entry.getValue().add(aclEntry);
					break;
				}
			}
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("END findAcls: objectIdentities: " + resultMap.keySet() + ", aclEntries: " + resultMap.values());
		}
		return resultMap;
	}

	public AclObjectIdentity findAclObjectIdentity(AclObjectIdentity objectId) {
		assertAclObjectIdentity(objectId);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclObjectIdentity: objectIdentity: " + objectId);
		}

		Row row = session.execute(QueryBuilder.select().all().from(KEYSPACE, AOI_TABLE).where(QueryBuilder.eq("id", objectId.getRowId()))).one();
		AclObjectIdentity objectIdentity = convertToAclObjectIdentity(row, true);

		if (LOG.isDebugEnabled()) {
			LOG.debug("END findAclObjectIdentity: objectIdentity: " + objectIdentity);
		}
		return objectIdentity;
	}

	public List<AclObjectIdentity> findAclObjectIdentityChildren(AclObjectIdentity objectId) {
		assertAclObjectIdentity(objectId);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclObjectIdentityChildren: objectIdentity: " + objectId);
		}
		List<AclObjectIdentity> result = new ArrayList<AclObjectIdentity>();

		ResultSet resultSet = session.execute(QueryBuilder.select().all().from(KEYSPACE, CHILDREN_TABLE)
				.where(QueryBuilder.eq("id", objectId.getRowId())));
		for (Row row : resultSet.all()) {
			result.add(convertToAclObjectIdentity(row, false));
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("END findAclObjectIdentityChildren: children: " + result);
		}
		return result;
	}

	public void deleteAcls(List<AclObjectIdentity> objectIdsToDelete) {
		assertAclObjectIdentityList(objectIdsToDelete);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN deleteAcls: objectIdsToDelete: " + objectIdsToDelete);
		}

		List<String> ids = new ArrayList<String>();
		for (AclObjectIdentity entry : objectIdsToDelete) {
			ids.add(entry.getRowId());
		}
		session.execute(QueryBuilder.delete().all().from(KEYSPACE, AOI_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		session.execute(QueryBuilder.delete().all().from(KEYSPACE, CHILDREN_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END deleteAcls");
		}
	}

	public void saveAcl(AclObjectIdentity aoi) throws AclAlreadyExistsException {
		assertAclObjectIdentity(aoi);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN saveAcl: aclObjectIdentity: " + aoi);
		}

		// Check this object identity hasn't already been persisted
		if (findAclObjectIdentity(aoi) != null) {
			throw new AclAlreadyExistsException("Object identity '" + aoi + "' already exists");
		}

		BoundStatement aoiBoundStatement = new BoundStatement(insertAoiStatement);		
		session.execute(aoiBoundStatement.bind(aoi.getRowId(), aoi.getId(), aoi.getObjectClass(), aoi.isEntriesInheriting(),
				aoi.getOwnerId(), aoi.isOwnerPrincipal(), aoi.getParentObjectId(), aoi.getParentObjectClass()));
		
		if (aoi.getParentRowId() != null) {
			BoundStatement childBoundStatement = new BoundStatement(insertChildStatement);
			session.execute(childBoundStatement.bind(aoi.getParentRowId(), aoi.getRowId(), aoi.getId(), aoi.getObjectClass()));
		}
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END saveAcl");
		}
	}

	public void updateAcl(AclObjectIdentity aoi, List<AclEntry> entries) throws AclNotFoundException {
		assertAclObjectIdentity(aoi);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN updateAcl: aclObjectIdentity: " + aoi + ", entries: " + entries);
		}

		// Check this object identity is already persisted
		AclObjectIdentity persistedAoi = findAclObjectIdentity(aoi);
		if (persistedAoi == null) {
			throw new AclNotFoundException("Object identity '" + aoi + "' does not exist");
		}

		// Update AOI
		BoundStatement aoiBoundStatement = new BoundStatement(insertAoiStatement);	
		session.execute(aoiBoundStatement.bind(aoi.getRowId(), aoi.getId(), aoi.getObjectClass(), aoi.isEntriesInheriting(),
				aoi.getOwnerId(), aoi.isOwnerPrincipal(), aoi.getParentObjectId(), aoi.getParentObjectClass()));
	
		// Check if parent is different and update children table
		if (!(persistedAoi.getParentRowId() == null ? aoi.getParentRowId() == null : persistedAoi.getParentRowId().equals(aoi.getParentRowId()))) {
			if (persistedAoi.getParentRowId() != null) {
				QueryBuilder.delete().all().from(KEYSPACE, CHILDREN_TABLE).where(QueryBuilder.eq("id", persistedAoi.getParentRowId())).and(QueryBuilder.eq("childId", aoi.getRowId()));
			}
			if (aoi.getParentRowId() != null) {
				BoundStatement childBoundStatement = new BoundStatement(insertChildStatement);
				session.execute(childBoundStatement.bind(aoi.getParentRowId(), aoi.getRowId(), aoi.getId(), aoi.getObjectClass()));
			}
		}
		
		// Update ACLs
		session.execute(QueryBuilder.delete().all().from(KEYSPACE, ACL_TABLE).where(QueryBuilder.eq("id", aoi.getRowId())));
		if (entries != null) {
			for (AclEntry entry : entries) {
				BoundStatement aclBoundStatement = new BoundStatement(insertAclStatement);
				session.execute(aclBoundStatement.bind(aoi.getRowId(), entry.getOrder(), entry.getSid(), entry.getMask(), entry.isSidPrincipal(),
						entry.isGranting(), entry.isAuditSuccess(), entry.isAuditFailure()));
			}
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("END updateAcl");
		}
	}

	private void assertAclObjectIdentityList(List<AclObjectIdentity> aoiList) {
		Assert.notEmpty(aoiList, "The AclObjectIdentity list cannot be empty");
		for (AclObjectIdentity aoi : aoiList) {
			assertAclObjectIdentity(aoi);
		}
	}

	private void assertAclObjectIdentity(AclObjectIdentity aoi) {
		Assert.notNull(aoi, "The AclObjectIdentity cannot be null");
		Assert.notNull(aoi.getId(), "The AclObjectIdentity id cannot be null");
		Assert.notNull(aoi.getObjectClass(), "The AclObjectIdentity objectClass cannot be null");
	}
	
	private AclObjectIdentity convertToAclObjectIdentity(Row row, boolean fullObject) {
		AclObjectIdentity result = null;
		if (row != null) {
			result = new AclObjectIdentity();
			result.setId(row.getString("objId"));
			result.setObjectClass(row.getString("objClass"));
			if (fullObject) {
				result.setOwnerId(row.getString("owner"));
				result.setEntriesInheriting(row.getBool("isInheriting"));
				result.setOwnerPrincipal(row.getBool("isOwnerPrincipal"));
				result.setParentObjectClass(row.getString("parentObjClass"));
				result.setParentObjectId(row.getString("parentObjId"));
			}			
		}		
		return result;
	}
	
	public void createAoisTable() {
		try {
			session.execute("CREATE TABLE " + KEYSPACE + ".aois (" 
					+ "id varchar PRIMARY KEY," 
					+ "objId varchar," 
					+ "objClass varchar," 
					+ "isInheriting boolean," 
					+ "owner varchar,"
					+ "isOwnerPrincipal boolean," 
					+ "parentObjId varchar,"
					+ "parentObjClass varchar"
					+ ");");
		} catch (AlreadyExistsException e) {
			LOG.warn(e);
		}
	}
	
	public void createChilrenTable() {
		try {
			session.execute("CREATE TABLE " + KEYSPACE + ".children (" 
					+ "id varchar," 
					+ "childId varchar,"
					+ "objId varchar,"
					+ "objClass varchar,"
					+ "PRIMARY KEY (id, childId)"
					+ ");");
		} catch (AlreadyExistsException e) {
			LOG.warn(e);
		}
	}
	
	public void createAclsTable() {
		try {
			session.execute("CREATE TABLE " + KEYSPACE + ".acls (" 
					+ "id varchar," 					
					+ "sid varchar," 
					+ "aclOrder int,"
					+ "mask int," 					
					+ "isSidPrincipal boolean,"
					+ "isGranting boolean," 
					+ "isAuditSuccess boolean," 
					+ "isAuditFailure boolean," 
					+ "PRIMARY KEY (id, sid, aclOrder)"
					+ ");");
		} catch (AlreadyExistsException e) {
			LOG.warn(e);
		}
	}

	public void createKeyspace() {	
		try {
			session.execute("CREATE KEYSPACE " + KEYSPACE 
					+ " WITH replication " + "= {'class':'SimpleStrategy', 'replication_factor':3};");
		} catch (AlreadyExistsException e) {
			LOG.warn(e);
		}
	}

}
