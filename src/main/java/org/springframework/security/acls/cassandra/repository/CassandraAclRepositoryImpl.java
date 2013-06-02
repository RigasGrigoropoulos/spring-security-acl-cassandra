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
import me.prettyprint.cassandra.service.template.MappedColumnFamilyResult;
import me.prettyprint.cassandra.service.template.ThriftColumnFamilyTemplate;
import me.prettyprint.hector.api.Cluster;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.factory.HFactory;

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

	private static final List<String> aoi_column_names = Arrays.asList(objectClass, parentObjectId, ownerSid, ownerIsPrincipal, entriesInheriting);
	private static final List<String> ae_column_names = Arrays.asList(aceOrder, sidIsPrincipal, mask, granting, auditSuccess, auditFailure);

	private ColumnFamilyTemplate<String, String> template;
	private final Keyspace ksp;

	public CassandraAclRepositoryImpl(Cluster cluster) {
		ksp = HFactory.createKeyspace(KEYSPACE, cluster);
		template = new ThriftColumnFamilyTemplate<String, String>(ksp, ACL_CF, StringSerializer.get(), StringSerializer.get());
	}

	public Map<AclObjectIdentity, List<AclEntry>> findAclEntries(List<String> objectIdsToLookup, List<String> sids) {
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
		return resultMap;
	}

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

	private class MyColumnFamilyRowMapper implements ColumnFamilyRowMapper<String, String, Entry<AclObjectIdentity, List<AclEntry>>> {

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
	};

}
