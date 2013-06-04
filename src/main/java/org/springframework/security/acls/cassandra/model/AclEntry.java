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

public class AclEntry {

	// id pattern: objectClass:objectId:sid
	private String id;
	private String sid;
	private boolean sidPrincipal;
	private int order;
	private int mask;
	private boolean granting;
	private boolean auditSuccess;
	private boolean auditFailure;


	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public boolean isSidPrincipal() {
		return sidPrincipal;
	}

	public void setSidPrincipal(boolean sidPrincipal) {
		this.sidPrincipal = sidPrincipal;
	}

	public String getSid() {
		return sid;
	}

	public void setSid(String sid) {
		this.sid = sid;
	}

	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public int getMask() {
		return mask;
	}

	public void setMask(int mask) {
		this.mask = mask;
	}

	public boolean isGranting() {
		return granting;
	}

	public void setGranting(boolean granting) {
		this.granting = granting;
	}

	public boolean isAuditSuccess() {
		return auditSuccess;
	}

	public void setAuditSuccess(boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
	}

	public boolean isAuditFailure() {
		return auditFailure;
	}

	public void setAuditFailure(boolean auditFailure) {
		this.auditFailure = auditFailure;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("AclEntry [").append("id: ").append(id);
		sb.append(", sid: ").append(sid);
		sb.append(", sidPrincipal: ").append(sidPrincipal);
		sb.append(", order: ").append(order);
		sb.append(", mask: ").append(mask);
		sb.append(", granting: ").append(granting);
		sb.append(", auditSuccess: ").append(auditSuccess);
		sb.append(", auditFailure: ").append(auditFailure).append("]");
		return sb.toString();
	}

}
