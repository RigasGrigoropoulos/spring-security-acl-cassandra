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

import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.service.template.ColumnFamilyResult;
import me.prettyprint.cassandra.service.template.ColumnFamilyRowMapper;
import me.prettyprint.cassandra.service.template.ColumnFamilyTemplate;
import me.prettyprint.cassandra.service.template.ColumnFamilyUpdater;
import me.prettyprint.cassandra.service.template.MappedColumnFamilyResult;
import me.prettyprint.cassandra.service.template.ThriftColumnFamilyTemplate;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.factory.HFactory;
import me.prettyprint.hector.api.mutation.Mutator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.cassandra.model.AclEntry;
import org.springframework.security.acls.cassandra.model.AclObjectIdentity;

public class CassandraAclRepositoryImpl implements CassandraAclRepository {

	private static final Log LOG = LogFactory.getLog(CassandraAclRepositoryImpl.class);

	private static final String COLUMN_NAME_TOKEN_SEPERATOR = "_:_";
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

	private static final List<String> aoi_column_names = Arrays.asList(objectClass, parentObjectId, ownerSid,
			ownerIsPrincipal, entriesInheriting);
	private static final List<String> ae_column_names = Arrays.asList(aceOrder, sidIsPrincipal, mask, granting,
			auditSuccess, auditFailure);

	private ColumnFamilyTemplate<String, String> template;
	private final Keyspace ksp;

	public CassandraAclRepositoryImpl(Cluster cluster) {
		ksp = HFactory.createKeyspace(KEYSPACE, cluster);
		template = new ThriftColumnFamilyTemplate<String, String>(ksp, ACL_CF, StringSerializer.get(),
				StringSerializer.get());
	}

	public Map<AclObjectIdentity, List<AclEntry>> findAcls(List<String> objectIdsToLookup, List<String> sids) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclEntries: objectIdentities: " + objectIdsToLookup + ", sids: " + sids);
		}
		Map<AclObjectIdentity, List<AclEntry>> resultMap = new HashMap<AclObjectIdentity, List<AclEntry>>();
		MappedColumnFamilyResult<String, String, Entry<AclObjectIdentity, List<AclEntry>>> result;

		// If sids not empty ask for specific columns
		if (sids != null && !sids.isEmpty()) {
			List<String> columnNames = new ArrayList<String>(aoi_column_names);
			for (String sid : sids) {
				for (String columnName : ae_column_names) {
					columnNames.add(sid + COLUMN_NAME_TOKEN_SEPERATOR + columnName);
				}
			}
			result = template.queryColumns(objectIdsToLookup, columnNames, new MyColumnFamilyRowMapper());
		} else {
			result = template.queryColumns(objectIdsToLookup, new MyColumnFamilyRowMapper());
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
			LOG.debug("END findAclEntries: objectIdentities: " + resultMap.keySet() + ", aclEntries: " + resultMap.values());
		}
		return resultMap;
	}

	public AclObjectIdentity findAclObjectIdentity(String objectId) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN findAclObjectIdentity: objectIdentity: " + objectId);
		}
		AclObjectIdentity objectIdentity;
		Entry<AclObjectIdentity, List<AclEntry>> result = template.queryColumns(objectId, new ArrayList<String>(
				aoi_column_names), new MyColumnFamilyRowMapper());
		objectIdentity = result.getKey();
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END findAclObjectIdentity: objectIdentity: " + objectIdentity);
		}
		return objectIdentity;
	}

	public List<AclObjectIdentity> findAclObjectIdentityChildren(String objectId) {
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

	public void deleteAcls(List<String> objectIdsToDelete) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN deleteAcls: objectIdsToDelete: " + objectIdsToDelete);
		}
		
		Mutator<String> mutator = template.createMutator();
		for (String entryId : objectIdsToDelete) {
			mutator.addDeletion(entryId, ACL_CF);
		}
		mutator.execute();	
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END deleteAcls");
		}
	}
	
	public void saveAcl(AclObjectIdentity aoi) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN saveAcl: aclObjectIdentity: " + aoi);
		}
		ColumnFamilyUpdater<String, String> updater = template.createUpdater(aoi.getId());
		updater.setString(objectClass, aoi.getObjectClass());
		updater.setBoolean(entriesInheriting, aoi.isEntriesInheriting());
		updater.setString(ownerSid, aoi.getOwnerId());
		updater.setBoolean(ownerIsPrincipal, aoi.isOwnerPrincipal());
		updater.setString(parentObjectId, aoi.getParentObjectId());		
		template.update(updater);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END saveAcl");
		}
	}
	
	public void updateAcl(AclObjectIdentity aoi, List<AclEntry> entries) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("BEGIN updateAcl: aclObjectIdentity: " + aoi + ", entries: " + entries);
		}
		
		Mutator<String> mutator = template.createMutator();
		mutator.addDeletion(aoi.getId(), ACL_CF);
		
		ColumnFamilyUpdater<String, String> updater = template.createUpdater(aoi.getId(), mutator);
		updater.setString(objectClass, aoi.getObjectClass());
		updater.setBoolean(entriesInheriting, aoi.isEntriesInheriting());
		updater.setString(ownerSid, aoi.getOwnerId());
		updater.setBoolean(ownerIsPrincipal, aoi.isOwnerPrincipal());
		updater.setString(parentObjectId, aoi.getParentObjectId());		
		
		for (AclEntry entry : entries) {
			updater.setInteger(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + aceOrder, entry.getOrder());
			updater.setInteger(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + mask, entry.getMask());
			updater.setBoolean(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + auditSuccess, entry.isAuditSuccess());
			updater.setBoolean(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + auditFailure, entry.isAuditFailure());
			updater.setBoolean(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + sidIsPrincipal, entry.isSidPrincipal());
			updater.setBoolean(entry.getSid() + COLUMN_NAME_TOKEN_SEPERATOR + granting, entry.isGranting());
		}
		template.update(updater);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("END updateAcl");
		}
	};

	private AclEntry getOrCreateAclEntry(List<AclEntry> aeList, String sid, String aclObjectId) {
		for (AclEntry entry : aeList) {
			if (entry.getSid().equals(sid)) {
				return entry;
			}
		}
		AclEntry entry = new AclEntry();
		entry.setSid(sid);
		entry.setId(aclObjectId + COLUMN_NAME_TOKEN_SEPERATOR + sid);
		entry.setObjectIdentity(aclObjectId);
		aeList.add(entry);
		return entry;
	}

	private String extractClassFromColumnName(String identifier) {
		return identifier.substring(0, identifier.indexOf(COLUMN_NAME_TOKEN_SEPERATOR));
	}

	private String extractSidFromColumnName(String identifier) {
		return identifier.substring(0, identifier.indexOf(COLUMN_NAME_TOKEN_SEPERATOR));
	}

	private class MyColumnFamilyRowMapper implements
			ColumnFamilyRowMapper<String, String, Entry<AclObjectIdentity, List<AclEntry>>> {

		public Entry<AclObjectIdentity, List<AclEntry>> mapRow(ColumnFamilyResult<String, String> results) {
			final AclObjectIdentity aoi = new AclObjectIdentity();
			aoi.setObjectClass(results.getString(objectClass));
			aoi.setEntriesInheriting(results.getBoolean(entriesInheriting));
			aoi.setId(results.getKey());
			aoi.setOwnerId(results.getString(ownerSid));
			aoi.setOwnerPrincipal(results.getBoolean(ownerIsPrincipal));
			aoi.setParentObjectId(results.getString(parentObjectId));

			final List<AclEntry> aeList = new ArrayList<AclEntry>();
			for (String columnName : results.getColumnNames()) {
				if (!aoi_column_names.contains(columnName)) {
					String sid = extractSidFromColumnName(columnName);
					AclEntry aclEntry = getOrCreateAclEntry(aeList, sid, results.getKey());
					if (columnName.endsWith(aceOrder)) {
						aclEntry.setOrder(results.getInteger(columnName));
					} else if (columnName.endsWith(sidIsPrincipal)) {
						aclEntry.setSidPrincipal(results.getBoolean(columnName));
					} else if (columnName.endsWith(mask)) {
						aclEntry.setMask(results.getInteger(columnName));
					} else if (columnName.endsWith(granting)) {
						aclEntry.setGranting(results.getBoolean(columnName));
					} else if (columnName.endsWith(auditSuccess)) {
						aclEntry.setAuditSuccess(results.getBoolean(columnName));
					} else if (columnName.endsWith(auditFailure)) {
						aclEntry.setAuditFailure(results.getBoolean(columnName));
					}
				}
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
	}
}
