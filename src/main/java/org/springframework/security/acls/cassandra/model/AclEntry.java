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

import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.Sid;

/**
 * DTO representing an individual permission assignment.
 * 
 * @author Rigas Grigoropoulos
 *
 */
public class AclEntry {

	// id pattern: objectClass:objectId:sid:order
	private String id;
	private String sid;
	private boolean sidPrincipal;
	private int order;
	private int mask;
	private boolean granting;
	private boolean auditSuccess;
	private boolean auditFailure;

	/**
	 * Constructs a new <code>AclEntry</code>.
	 */
	public AclEntry() {}
	
	/**
	 * Constructs a new <code>AclEntry</code> out of the provided <code>AccessControlEntry</code>.
	 * 
	 * @param ace the <code>AccessControlEntry</code> to use for parameter population.
	 */
	public AclEntry(AccessControlEntry ace) {
		granting = ace.isGranting();
		id = (String) ace.getId();
		mask = ace.getPermission().getMask();
		order = ace.getAcl().getEntries().indexOf(ace);
		
		if (ace.getAcl().getOwner() instanceof PrincipalSid) {
			sid = ((PrincipalSid) ace.getSid()).getPrincipal();
			sidPrincipal = true;
		} else if (ace.getAcl().getOwner() instanceof GrantedAuthoritySid) {
			sid = ((GrantedAuthoritySid) ace.getSid()).getGrantedAuthority();
			sidPrincipal = false;
		}
		
		if (ace instanceof AuditableAccessControlEntry) {
			auditSuccess = ((AuditableAccessControlEntry) ace).isAuditFailure();
			auditFailure =  ((AuditableAccessControlEntry) ace).isAuditSuccess();
		} else {
			auditSuccess = false;
			auditFailure = false;
		}
	}
	
	/**
	 * @return the identifier of this <code>AclEntry</code>. 
	 * 		The identifier follows the pattern 'objectClass:objectId:sid:order'.
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the identifier for this <code>AclEntry</code>. 
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * @return true if the Sid for this <code>AclEntry</code> is of type <code>PrincipalSid</code>
	 * 		of false if it is of type <code>GrantedAuthoritySid</code>. 
	 */
	public boolean isSidPrincipal() {
		return sidPrincipal;
	}

	/**
	 * @param sidPrincipal whether the Sid for this <code>AclEntry</code> is of type <code>PrincipalSid</code>.
	 */
	public void setSidPrincipal(boolean sidPrincipal) {
		this.sidPrincipal = sidPrincipal;
	}

	/**
	 * @return the identifier of the Sid for this <code>AclEntry</code>.
	 */
	public String getSid() {
		return sid;
	}
	
	/**
	 * @return the <code>Sid</code> object for this <code>AclEntry</code>.
	 */
	public Sid getSidObject() {
		Sid result = null;
		if (sidPrincipal) {
			result = new PrincipalSid(sid);
		} else {
			result = new GrantedAuthoritySid(sid);
		}
		return result;
	}

	/**
	 * @param sid the identifier of the Sid for this <code>AclEntry</code>.
	 */
	public void setSid(String sid) {
		this.sid = sid;
	}

	/**
	 * @return
	 */
	public int getOrder() {
		return order;
	}

	/**
	 * @param order
	 */
	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * @return
	 */
	public int getMask() {
		return mask;
	}

	/**
	 * @param mask
	 */
	public void setMask(int mask) {
		this.mask = mask;
	}

	/**
	 * @return
	 */
	public boolean isGranting() {
		return granting;
	}

	/**
	 * @param granting
	 */
	public void setGranting(boolean granting) {
		this.granting = granting;
	}

	/**
	 * @return
	 */
	public boolean isAuditSuccess() {
		return auditSuccess;
	}

	/**
	 * @param auditSuccess
	 */
	public void setAuditSuccess(boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
	}

	/**
	 * @return
	 */
	public boolean isAuditFailure() {
		return auditFailure;
	}

	/**
	 * @param auditFailure
	 */
	public void setAuditFailure(boolean auditFailure) {
		this.auditFailure = auditFailure;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
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
