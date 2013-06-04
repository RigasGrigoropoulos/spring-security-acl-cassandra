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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import me.prettyprint.cassandra.serializers.BooleanSerializer;
import me.prettyprint.cassandra.serializers.CompositeSerializer;
import me.prettyprint.cassandra.serializers.IntegerSerializer;
import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.service.template.ColumnFamilyResult;
import me.prettyprint.cassandra.service.template.ColumnFamilyRowMapper;
import me.prettyprint.cassandra.service.template.ColumnFamilyTemplate;
import me.prettyprint.cassandra.service.template.MappedColumnFamilyResult;
import me.prettyprint.cassandra.service.template.ThriftColumnFamilyTemplate;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.ResultStatus;
import me.prettyprint.hector.api.beans.AbstractComposite.ComponentEquality;
import me.prettyprint.hector.api.beans.Composite;
import me.prettyprint.hector.api.factory.HFactory;
import me.prettyprint.hector.api.mutation.MutationResult;
import me.prettyprint.hector.api.mutation.Mutator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;
import org.springframework.security.acls.cassandra.repository.exceptions.AclAlreadyExistsException;
import org.springframework.security.acls.cassandra.repository.exceptions.AclNotFoundException;
import org.springframework.util.Assert;

public class CassandraAclRepositoryImpl implements CassandraAclRepository {

	private static final Log LOG = LogFactory.getLog(CassandraAclRepositoryImpl.class);

	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String ACL_CF = "AclColumnFamily";

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

	private final Map<String, Composite> aoi_column_names;
	private final static List<String> ae_column_names = Arrays.asList(new String[] { aceOrder, sidIsPrincipal, granting, mask, auditSuccess, auditFailure });
 
	private ColumnFamilyTemplate<Composite, Composite> template;
	private final Keyspace ksp;

	public CassandraAclRepositoryImpl(Cluster cluster) {
		ksp = HFactory.createKeyspace(KEYSPACE, cluster);
		template = new ThriftColumnFamilyTemplate<Composite, Composite>(ksp, ACL_CF, CompositeSerializer.get(),
				CompositeSerializer.get());
		aoi_column_names = new HashMap<String, Composite>();
		aoi_column_names.put(objectClass, createCompositeKey(objectClass));
		aoi_column_names.put(parentObjectId, createCompositeKey(parentObjectId));
		aoi_column_names.put(ownerSid, createCompositeKey(ownerSid));
		aoi_column_names.put(ownerIsPrincipal, createCompositeKey(ownerIsPrincipal));
		aoi_column_names.put(entriesInheriting, createCompositeKey(entriesInheriting));
	}

	public Map<AclObjectIdentity, List<AclEntry>> findAcls(List<AclObjectIdentity> objectIdsToLookup, List<String> sids) {
		assertAclObjectIdentityList(objectIdsToLookup);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclEntries: objectIdentities: " + objectIdsToLookup + ", sids: " + sids);
		}
		Map<AclObjectIdentity, List<AclEntry>> resultMap = new HashMap<AclObjectIdentity, List<AclEntry>>();
		MappedColumnFamilyResult<Composite, Composite, Entry<AclObjectIdentity, List<AclEntry>>> result;

		// If sids not empty ask for specific columns
		if (sids != null && !sids.isEmpty()) {
			List<Composite> columnNames = new ArrayList<Composite>(aoi_column_names.values());
			for (String sid : sids) {
				for (String columnName : ae_column_names) {
					Composite sidColumn = createCompositeKey(sid, columnName);
					columnNames.add(sidColumn);
				}
			}
			result = template.queryColumns(createCompositeKeys(objectIdsToLookup), columnNames, new MyColumnFamilyRowMapper());
		} else {
			result = template.queryColumns(createCompositeKeys(objectIdsToLookup), new MyColumnFamilyRowMapper());
		}

		if (result != null && result.hasResults()) {
			boolean done = false;
			do {
				Entry<AclObjectIdentity, List<AclEntry>> entry = result.getRow();
				resultMap.put(entry.getKey(), entry.getValue());
				if (result.hasNext()) {
					result.next();
				} else {
					done = true;
				}
			} while (!done);
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("END findAclEntries: objectIdentities: " + resultMap.keySet() + ", aclEntries: "
					+ resultMap.values());
		}
		return resultMap;
	}

	public AclObjectIdentity findAclObjectIdentity(AclObjectIdentity objectId) {
		assertAclObjectIdentity(objectId);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclObjectIdentity: objectIdentity: " + objectId);
		}
		AclObjectIdentity objectIdentity = null;
		Entry<AclObjectIdentity, List<AclEntry>> result = template.queryColumns(createCompositeKey(objectId), new ArrayList<Composite>(
				aoi_column_names.values()), new MyColumnFamilyRowMapper());
		if (result != null) {
			objectIdentity = result.getKey();
		}

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

		// TODO Auto-generated method stub

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

		Mutator<Composite> mutator = template.createMutator();
		for (Composite entryId : createCompositeKeys(objectIdsToDelete)) {
			mutator.addDeletion(entryId, ACL_CF);
		}
		MutationResult result = mutator.execute();

		if (LOG.isDebugEnabled()) {
			LOG.debug("END deleteAcls " + getResultInfoString(result));
		}
	}

	public void saveAcl(AclObjectIdentity aoi) {
		assertAclObjectIdentity(aoi);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN saveAcl: aclObjectIdentity: " + aoi);
		}
		
		// Check this object identity hasn't already been persisted
		if (findAclObjectIdentity(aoi) != null) {
			throw new AclAlreadyExistsException("Object identity '" + aoi + "' already exists");
		}

		Mutator<Composite> mutator = HFactory.createMutator(ksp, CompositeSerializer.get());
		addAclObjectIdentityInsertions(aoi, mutator);	
		MutationResult result = mutator.execute();

		if (LOG.isDebugEnabled()) {
			LOG.debug("END saveAcl " + getResultInfoString(result));
		}
	}
	
	public void updateAcl(AclObjectIdentity aoi, List<AclEntry> entries) {
		assertAclObjectIdentity(aoi);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN updateAcl: aclObjectIdentity: " + aoi + ", entries: " + entries);
		}
		
		// Check this object identity is already persisted
		if (findAclObjectIdentity(aoi) == null) {
			throw new AclNotFoundException("Object identity '" + aoi + "' does not exist");
		}
	
		Composite aclId = createCompositeKey(aoi);
		Mutator<Composite> mutator = HFactory.createMutator(ksp, CompositeSerializer.get());
		mutator.addDeletion(aclId, ACL_CF);
		addAclObjectIdentityInsertions(aoi, mutator);		
	
		if (entries != null) {
			for (AclEntry entry : entries) {
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(
						createCompositeKey(entry.getSid(), aceOrder), entry.getOrder(), new CompositeSerializer(),
						IntegerSerializer.get()));
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(createCompositeKey(entry.getSid(), mask),
						entry.getMask(), new CompositeSerializer(), IntegerSerializer.get()));
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(
						createCompositeKey(entry.getSid(), auditSuccess), entry.isAuditSuccess(),
						new CompositeSerializer(), BooleanSerializer.get()));
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(
						createCompositeKey(entry.getSid(), auditFailure), entry.isAuditFailure(),
						new CompositeSerializer(), BooleanSerializer.get()));
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(
						createCompositeKey(entry.getSid(), sidIsPrincipal), entry.isSidPrincipal(),
						new CompositeSerializer(), BooleanSerializer.get()));
				mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(
						createCompositeKey(entry.getSid(), granting), entry.isGranting(), new CompositeSerializer(),
						BooleanSerializer.get()));
			}
		}
		
		MutationResult result = mutator.execute();
	
		if (LOG.isDebugEnabled()) {
			LOG.debug("END updateAcl " + getResultInfoString(result));
		}
	}
	
	private void assertAclObjectIdentityList(List<AclObjectIdentity> aoiList) {
		Assert.notNull(aoiList, "The AclObjectIdentity list cannot be null");
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
	
	private void addAclObjectIdentityInsertions(AclObjectIdentity aoi, Mutator<Composite> mutator) {
		Composite aclId = createCompositeKey(aoi);
		mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(aoi_column_names.get(objectClass),
				aoi.getObjectClass(), new CompositeSerializer(), StringSerializer.get()));
		mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(aoi_column_names.get(entriesInheriting),
				aoi.isEntriesInheriting(), new CompositeSerializer(), BooleanSerializer.get()));
		mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(aoi_column_names.get(ownerSid),
				aoi.getOwnerId(), new CompositeSerializer(), StringSerializer.get()));
		mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(aoi_column_names.get(ownerIsPrincipal),
				aoi.isOwnerPrincipal(), new CompositeSerializer(), BooleanSerializer.get()));
		if (aoi.getParentObjectId() != null && !aoi.getParentObjectId().isEmpty()) {
			mutator.addInsertion(aclId, ACL_CF, HFactory.createColumn(aoi_column_names.get(parentObjectId),
					aoi.getParentObjectId(), new CompositeSerializer(), StringSerializer.get()));
		}
	}

	private String getResultInfoString(ResultStatus resultStatus) {
		return "took " + resultStatus.getExecutionTimeMicro() + " ms on host " + resultStatus.getHostUsed().getUrl();
	}
	
	private List<Composite> createCompositeKeys(List<AclObjectIdentity> objectIds) {
		List<Composite> result = new ArrayList<Composite>();
		for (AclObjectIdentity objectId : objectIds) {
			result.add(createCompositeKey(objectId));
		}
		return result;
	}
	
	private Composite createCompositeKey(AclObjectIdentity objectId) {
		return createCompositeKey(objectId.getObjectClass(), objectId.getId());
	}

	private Composite createCompositeKey(String... params) {
		Composite columnKey = new Composite();
		for (String param : params) {
			columnKey.addComponent(param, StringSerializer.get());
		}
		return columnKey;
	}

	private AclEntry getOrCreateAclEntry(List<AclEntry> aeList, String sid, String aclObjectId, String aclObjectClass) {
		for (AclEntry entry : aeList) {
			if (entry.getSid().equals(sid)) {
				return entry;
			}
		}
		AclEntry entry = new AclEntry();
		entry.setSid(sid);
		entry.setId(aclObjectClass + ":" + aclObjectId + ":" + sid);
		aeList.add(entry);
		return entry;
	}

	private class MyColumnFamilyRowMapper implements
			ColumnFamilyRowMapper<Composite, Composite, Entry<AclObjectIdentity, List<AclEntry>>> {

		public Entry<AclObjectIdentity, List<AclEntry>> mapRow(ColumnFamilyResult<Composite, Composite> results) {
			if (results.hasResults()) {
				final List<AclEntry> aeList = new ArrayList<AclEntry>();
				final AclObjectIdentity aoi = new AclObjectIdentity();
				aoi.setId(results.getKey().get(1, StringSerializer.get()));
				aoi.setObjectClass(results.getKey().get(0, StringSerializer.get()));

				for (Composite columnName : results.getColumnNames()) {
					String firstColumnNameComponent = columnName.get(0, StringSerializer.get());
					if (aoi_column_names.keySet().contains(firstColumnNameComponent)) {
						if (firstColumnNameComponent.equals(entriesInheriting)) {
							aoi.setEntriesInheriting(results.getBoolean(columnName));
						} else if (firstColumnNameComponent.equals(ownerSid)) {
							aoi.setOwnerId(results.getString(columnName));
						} else if (firstColumnNameComponent.equals(ownerIsPrincipal)) {
							aoi.setOwnerPrincipal(results.getBoolean(columnName));
						} else if (firstColumnNameComponent.equals(parentObjectId)) {
							aoi.setParentObjectId(results.getString(columnName));
						}
					} else {
						String sid = firstColumnNameComponent;
						String secondColumnNameComponent = columnName.get(1, StringSerializer.get());
						AclEntry aclEntry = getOrCreateAclEntry(aeList, sid, aoi.getId(), aoi.getObjectClass());
						if (secondColumnNameComponent.equals(aceOrder)) {
							aclEntry.setOrder(results.getInteger(columnName));
						} else if (secondColumnNameComponent.equals(sidIsPrincipal)) {
							aclEntry.setSidPrincipal(results.getBoolean(columnName));
						} else if (secondColumnNameComponent.equals(mask)) {
							aclEntry.setMask(results.getInteger(columnName));
						} else if (secondColumnNameComponent.equals(granting)) {
							aclEntry.setGranting(results.getBoolean(columnName));
						} else if (secondColumnNameComponent.equals(auditSuccess)) {
							aclEntry.setAuditSuccess(results.getBoolean(columnName));
						} else if (secondColumnNameComponent.equals(auditFailure)) {
							aclEntry.setAuditFailure(results.getBoolean(columnName));
						}
					}
				}

				if (LOG.isDebugEnabled()) {
					LOG.debug("Query " + getResultInfoString(results));
				}

				return new Entry<AclObjectIdentity, List<AclEntry>>() {

					public List<AclEntry> setValue(List<AclEntry> value) {
						throw new UnsupportedOperationException("Cannot modify the value");
					}

					public List<AclEntry> getValue() {
						return aeList;
					}

					public AclObjectIdentity getKey() {
						return aoi;
					}
				};
			}
			return null;
		}
	}
}
