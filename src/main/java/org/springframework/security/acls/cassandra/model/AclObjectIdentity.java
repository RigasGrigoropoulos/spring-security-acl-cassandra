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
package org.springframework.security.acls.cassandra.model;

import org.springframework.security.acls.model.ObjectIdentity;

public class AclObjectIdentity {

	private String id;
	private String objectClass;
	private String parentObjectId;
	private String ownerId;
	private boolean ownerPrincipal;
	private boolean entriesInheriting;

	public AclObjectIdentity() {}
	
	public AclObjectIdentity(ObjectIdentity objectIdentity) {
		objectClass = objectIdentity.getType();
		id = (String) objectIdentity.getIdentifier();
	}
	
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getObjectClass() {
		return objectClass;
	}

	public boolean isOwnerPrincipal() {
		return ownerPrincipal;
	}

	public void setOwnerPrincipal(boolean ownerPrincipal) {
		this.ownerPrincipal = ownerPrincipal;
	}

	public void setObjectClass(String objectClass) {
		this.objectClass = objectClass;
	}

	public String getParentObjectId() {
		return parentObjectId;
	}

	public void setParentObjectId(String parentObjectId) {
		this.parentObjectId = parentObjectId;
	}

	public String getOwnerId() {
		return ownerId;
	}

	public void setOwnerId(String ownerId) {
		this.ownerId = ownerId;
	}

	public boolean isEntriesInheriting() {
		return entriesInheriting;
	}

	public void setEntriesInheriting(boolean entriesInheriting) {
		this.entriesInheriting = entriesInheriting;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("AclObjectIdentity [").append("id: ").append(id);
		sb.append(", objectClass: ").append(objectClass);
		sb.append(", parentObjectId: ").append(parentObjectId);
		sb.append(", ownerId: ").append(ownerId);
		sb.append(", ownerPrincipal: ").append(ownerPrincipal);
		sb.append(", entriesInheriting: ").append(entriesInheriting).append("]");
		return sb.toString();
	}

}
