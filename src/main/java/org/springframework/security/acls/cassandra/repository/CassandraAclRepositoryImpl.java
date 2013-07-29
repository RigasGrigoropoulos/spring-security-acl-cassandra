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

import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.exceptions.AlreadyExistsException;
import com.datastax.driver.core.querybuilder.Batch;
import com.datastax.driver.core.querybuilder.QueryBuilder;

/**
 * Implementation of <code>CassandraAclRepository</code> using the DataStax Java Driver.
 * 
 * @author Rigas Grigoropoulos
 *
 */
public class CassandraAclRepositoryImpl implements CassandraAclRepository {

	private static final Log LOG = LogFactory.getLog(CassandraAclRepositoryImpl.class);

	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String AOI_TABLE = "aois";
	private static final String CHILDREN_TABLE = "children";
	private static final String ACL_TABLE = "acls";
	
	private static final String[] AOI_KEYS = new String[] { "id", "objId", "objClass", "isInheriting", "owner", "isOwnerPrincipal", "parentObjId", "parentObjClass" };
	private static final String[] CHILD_KEYS = new String[] { "id", "childId", "objId", "objClass" };
	private static final String[] ACL_KEYS = new String[] { "id", "aclOrder", "sid", "mask", "isSidPrincipal", "isGranting", "isAuditSuccess", "isAuditFailure" };

	private String replicationStrategy = "SimpleStrategy";
	private int replicationFactor = 3;
	
	private Session session;

	/**
	 * Constructs a new <code>CassandraAclRepositoryImpl</code>.
	 * 
	 * @param session the <code>Session</code> to use for connectivity with Cassandra.
	 */
	public CassandraAclRepositoryImpl(Session session) {
		this.session = session;
	}
	
	/**
	 * Constructs a new <code>CassandraAclRepositoryImpl</code> and optionally creates 
	 * the Cassandra keyspace and schema for storing ACLs.
	 * 
	 * @param session the <code>Session</code> to use for connectivity with Cassandra.
	 * @param initSchema whether the keyspace and schema for storing ACLs should be created.
	 * @param replicationStrategy the replication strategy to use when creating the keyspace.
	 * @param replicationFactor the replication factor to use when creating the keyspace.
	 */
	public CassandraAclRepositoryImpl(Session session, boolean initSchema, String replicationStrategy, int replicationFactor) {
		this(session);
		if (initSchema) {
			this.replicationFactor = replicationFactor;
			this.replicationStrategy = replicationStrategy;
			
			createKeyspace();
			createAoisTable();
			createChilrenTable();
			createAclsTable();
		}
	}
	
	/**
	 * Constructs a new <code>CassandraAclRepositoryImpl</code> and optionally creates 
	 * the Cassandra keyspace and schema for storing ACLs.
	 * 
	 * @param session the <code>Session</code> to use for connectivity with Cassandra.
	 * @param initSchema whether the keyspace and schema for storing ACLs should be created.
	 */
	public CassandraAclRepositoryImpl(Session session, boolean initSchema) {
		this(session);
		if (initSchema) {
			createKeyspace();
			createAoisTable();
			createChilrenTable();
			createAclsTable();
		}
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#findAcls(java.util.List)
	 */
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
					return new Integer(o1.getOrder()).compareTo(o2.getOrder());
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

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#findAclObjectIdentity(org.springframework.security.acls.cassandra.model.AclObjectIdentity)
	 */
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

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#findAclObjectIdentityChildren(org.springframework.security.acls.cassandra.model.AclObjectIdentity)
	 */
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

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#deleteAcls(java.util.List)
	 */
	public void deleteAcls(List<AclObjectIdentity> objectIdsToDelete) {
		assertAclObjectIdentityList(objectIdsToDelete);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN deleteAcls: objectIdsToDelete: " + objectIdsToDelete);
		}

		List<String> ids = new ArrayList<String>();
		for (AclObjectIdentity entry : objectIdsToDelete) {
			ids.add(entry.getRowId());
		}
		Batch batch = QueryBuilder.batch();
		batch.add(QueryBuilder.delete().all().from(KEYSPACE, AOI_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		batch.add(QueryBuilder.delete().all().from(KEYSPACE, CHILDREN_TABLE).where(QueryBuilder.in("id", ids.toArray())));
		session.execute(batch);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END deleteAcls");
		}
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#saveAcl(org.springframework.security.acls.cassandra.model.AclObjectIdentity)
	 */
	public void saveAcl(AclObjectIdentity aoi) throws AclAlreadyExistsException {
		assertAclObjectIdentity(aoi);

		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN saveAcl: aclObjectIdentity: " + aoi);
		}

		// Check this object identity hasn't already been persisted
		if (findAclObjectIdentity(aoi) != null) {
			throw new AclAlreadyExistsException("Object identity '" + aoi + "' already exists");
		}
		
		Batch batch = QueryBuilder.batch();
		batch.add(QueryBuilder.insertInto(KEYSPACE, AOI_TABLE).values(AOI_KEYS, new Object[] { aoi.getRowId(), aoi.getId(), aoi.getObjectClass(), aoi.isEntriesInheriting(),
				aoi.getOwnerId(), aoi.isOwnerPrincipal(), aoi.getParentObjectId(), aoi.getParentObjectClass() }));
		
		if (aoi.getParentRowId() != null) {
			batch.add(QueryBuilder.insertInto(KEYSPACE, CHILDREN_TABLE).values(CHILD_KEYS, new Object[] { aoi.getParentRowId(), aoi.getRowId(), aoi.getId(), aoi.getObjectClass() }));
		}
		session.execute(batch);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END saveAcl");
		}
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.acls.cassandra.repository.CassandraAclRepository#updateAcl(org.springframework.security.acls.cassandra.model.AclObjectIdentity, java.util.List)
	 */
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
		
		// Update AOI & delete existing ACLs
		Batch batch = QueryBuilder.batch();
		batch.add(QueryBuilder.insertInto(KEYSPACE, AOI_TABLE).values(AOI_KEYS, new Object[] { aoi.getRowId(), aoi.getId(), aoi.getObjectClass(), aoi.isEntriesInheriting(),
				aoi.getOwnerId(), aoi.isOwnerPrincipal(), aoi.getParentObjectId(), aoi.getParentObjectClass() }));
		batch.add(QueryBuilder.delete().all().from(KEYSPACE, ACL_TABLE).where(QueryBuilder.eq("id", aoi.getRowId())));
	
		// Check if parent is different and delete from children table
		boolean parentChanged = false;
		if (!(persistedAoi.getParentRowId() == null ? aoi.getParentRowId() == null : persistedAoi.getParentRowId().equals(aoi.getParentRowId()))) {
			parentChanged = true;
			
			if (persistedAoi.getParentRowId() != null) {
				batch.add(QueryBuilder.delete().all().from(KEYSPACE, CHILDREN_TABLE).where(QueryBuilder.eq("id", persistedAoi.getParentRowId())).and(QueryBuilder.eq("childId", aoi.getRowId())));
			}			
		}
		session.execute(batch);
		
		// Update ACLs & children table	
		batch = QueryBuilder.batch();
		boolean executeBatch = false;
		
		if (entries != null && !entries.isEmpty()) {
			for (AclEntry entry : entries) {
				batch.add(QueryBuilder.insertInto(KEYSPACE, ACL_TABLE).values(ACL_KEYS, new Object[] { aoi.getRowId(), entry.getOrder(), entry.getSid(), entry.getMask(), entry.isSidPrincipal(),
						entry.isGranting(), entry.isAuditSuccess(), entry.isAuditFailure() }));
			}
			executeBatch = true;
		}		
		if (parentChanged) {
			if (aoi.getParentRowId() != null) {
				batch.add(QueryBuilder.insertInto(KEYSPACE, CHILDREN_TABLE).values(CHILD_KEYS, new Object[] { aoi.getParentRowId(), aoi.getRowId(), aoi.getId(), aoi.getObjectClass() }));
			}
			executeBatch = true;
		}
		if (executeBatch) {
			session.execute(batch);
		}		

		if (LOG.isDebugEnabled()) {
			LOG.debug("END updateAcl");
		}
	}

	/**
	 * Validates all <code>AclObjectIdentity</code> objects in the list.
	 * 
	 * @param aoiList a list of <code>AclObjectIdentity</code> objects to validate.
	 */
	private void assertAclObjectIdentityList(List<AclObjectIdentity> aoiList) {
		Assert.notEmpty(aoiList, "The AclObjectIdentity list cannot be empty");
		for (AclObjectIdentity aoi : aoiList) {
			assertAclObjectIdentity(aoi);
		}
	}

	/**
	 * Validates an <code>AclObjectIdentity</code> object.
	 * 
	 * @param aoi the <code>AclObjectIdentity</code> object to validate.
	 */
	private void assertAclObjectIdentity(AclObjectIdentity aoi) {
		Assert.notNull(aoi, "The AclObjectIdentity cannot be null");
		Assert.notNull(aoi.getId(), "The AclObjectIdentity id cannot be null");
		Assert.notNull(aoi.getObjectClass(), "The AclObjectIdentity objectClass cannot be null");
	}
	
	/**
	 * Converts a <code>Row</code> from a Cassandra result to an <code>AclObjectIdentity</code> object.
	 * 
	 * @param row the <code>Row</code> representing an <code>AclObjectIdentity</code>. 
	 * @param fullObject whether the returned <code>AclObjectIdentity</code> object will 
	 * 		contain only identification parameters or will be fully populated.
	 * @return an <code>AclObjectIdentity</code> object with the values retrieved from Cassandra.
	 */
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
	
	/**
	 * Creates the schema for the table holding <code>AclObjectIdentity</code> representations.
	 */
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
	
	/**
	 * Creates the schema for the table holding <code>AclObjectIdentity</code> children.
	 */
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
	
	/**
	 * Creates the schema for the table holding <code>AclEntry</code> representations.
	 */
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

	/**
	 * Creates the schema for the 'SpringSecurityAclCassandra' keyspace.
	 */
	public void createKeyspace() {	
		try {
			session.execute("CREATE KEYSPACE " + KEYSPACE 
					+ " WITH replication " + "= {'class':'" + replicationStrategy + "', 'replication_factor':" + replicationFactor + "};");
		} catch (AlreadyExistsException e) {
			LOG.warn(e);
		}
	}

}
