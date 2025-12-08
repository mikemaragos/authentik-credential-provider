"""
AD Manager Module
Handles LDAP operations for Active Directory user management.
"""

import logging
from typing import List, Optional
import ldap3
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_ADD, SUBTREE

logger = logging.getLogger('CertIssuer.ADManager')


class ADManager:
    """Handles Active Directory operations via LDAP."""
    
    def __init__(self, server: str, base_dn: str, bind_user: str, bind_password: str):
        """
        Initialize AD Manager.
        
        Args:
            server: LDAP server URL (e.g., ldap://dc.domain.local or ldaps://dc.domain.local)
            base_dn: Base DN for searches (e.g., DC=test,DC=local)
            bind_user: Bind user DN or UPN
            bind_password: Bind user password
        """
        self.server_url = server
        self.base_dn = base_dn
        self.bind_user = bind_user
        self.bind_password = bind_password
        self._conn = None
        
        logger.info(f"ADManager initialized: server={server}, base_dn={base_dn}")
    
    def _get_connection(self) -> Connection:
        """Get or create LDAP connection."""
        if self._conn and self._conn.bound:
            return self._conn
        
        try:
            # Parse server URL
            use_ssl = self.server_url.startswith('ldaps://')
            server_host = self.server_url.replace('ldaps://', '').replace('ldap://', '')
            
            server = Server(
                server_host,
                port=636 if use_ssl else 389,
                use_ssl=use_ssl,
                get_info=ALL
            )
            
            self._conn = Connection(
                server,
                user=self.bind_user,
                password=self.bind_password,
                auto_bind=True,
                authentication=ldap3.NTLM if '\\' in self.bind_user else ldap3.SIMPLE
            )
            
            logger.info(f"LDAP connection established to {server_host}")
            return self._conn
            
        except Exception as e:
            logger.exception(f"Failed to connect to LDAP: {e}")
            raise
    
    def find_user_dn(self, username: str) -> Optional[str]:
        """
        Find user's Distinguished Name by sAMAccountName or UPN.
        
        Args:
            username: Username (sAMAccountName) or UPN
        
        Returns:
            User's DN or None if not found
        """
        conn = self._get_connection()
        
        # Build search filter
        if '@' in username:
            # UPN search
            search_filter = f'(userPrincipalName={username})'
        else:
            # sAMAccountName search
            search_filter = f'(sAMAccountName={username})'
        
        try:
            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if conn.entries:
                dn = str(conn.entries[0].distinguishedName)
                logger.info(f"Found user DN: {dn}")
                return dn
            else:
                logger.warning(f"User not found: {username}")
                return None
                
        except Exception as e:
            logger.exception(f"Error searching for user: {e}")
            return None
    
    def get_alt_security_identities(self, username: str) -> List[str]:
        """
        Get current altSecurityIdentities attribute values for a user.
        
        Args:
            username: Username to look up
        
        Returns:
            List of altSecurityIdentities values
        """
        conn = self._get_connection()
        user_dn = self.find_user_dn(username)
        
        if not user_dn:
            return []
        
        try:
            conn.search(
                search_base=user_dn,
                search_filter='(objectClass=user)',
                search_scope=ldap3.BASE,
                attributes=['altSecurityIdentities']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, 'altSecurityIdentities'):
                    values = list(entry.altSecurityIdentities)
                    logger.info(f"altSecurityIdentities for {username}: {values}")
                    return values
            
            return []
            
        except Exception as e:
            logger.exception(f"Error getting altSecurityIdentities: {e}")
            return []
    
    def set_alt_security_identity(self, username: str, mapping: str, replace: bool = True) -> bool:
        """
        Set altSecurityIdentities attribute for a user.
        
        Args:
            username: Username to update
            mapping: Mapping value (e.g., "X509:<SKI>abc123")
            replace: If True, replace existing values. If False, add to existing.
        
        Returns:
            True on success, False on failure
        """
        conn = self._get_connection()
        user_dn = self.find_user_dn(username)
        
        if not user_dn:
            logger.error(f"Cannot set mapping - user not found: {username}")
            return False
        
        try:
            if replace:
                # Replace all existing values
                result = conn.modify(
                    user_dn,
                    {'altSecurityIdentities': [(MODIFY_REPLACE, [mapping])]}
                )
            else:
                # Add to existing values
                result = conn.modify(
                    user_dn,
                    {'altSecurityIdentities': [(MODIFY_ADD, [mapping])]}
                )
            
            if result:
                logger.info(f"Successfully set altSecurityIdentities for {username}: {mapping}")
                return True
            else:
                logger.error(f"Failed to modify altSecurityIdentities: {conn.result}")
                return False
                
        except Exception as e:
            logger.exception(f"Error setting altSecurityIdentities: {e}")
            return False
    
    def clear_alt_security_identities(self, username: str) -> bool:
        """
        Clear all altSecurityIdentities for a user.
        
        Args:
            username: Username to clear
        
        Returns:
            True on success
        """
        conn = self._get_connection()
        user_dn = self.find_user_dn(username)
        
        if not user_dn:
            return False
        
        try:
            result = conn.modify(
                user_dn,
                {'altSecurityIdentities': [(MODIFY_REPLACE, [])]}
            )
            
            if result:
                logger.info(f"Cleared altSecurityIdentities for {username}")
            
            return result
            
        except Exception as e:
            logger.exception(f"Error clearing altSecurityIdentities: {e}")
            return False
    
    def get_user_info(self, username: str) -> Optional[dict]:
        """
        Get user information from AD.
        
        Args:
            username: Username to look up
        
        Returns:
            Dict with user attributes or None
        """
        conn = self._get_connection()
        
        if '@' in username:
            search_filter = f'(userPrincipalName={username})'
        else:
            search_filter = f'(sAMAccountName={username})'
        
        try:
            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    'distinguishedName',
                    'sAMAccountName', 
                    'userPrincipalName',
                    'mail',
                    'displayName',
                    'objectSid',
                    'altSecurityIdentities'
                ]
            )
            
            if conn.entries:
                entry = conn.entries[0]
                return {
                    'dn': str(entry.distinguishedName) if hasattr(entry, 'distinguishedName') else None,
                    'sAMAccountName': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else None,
                    'userPrincipalName': str(entry.userPrincipalName) if hasattr(entry, 'userPrincipalName') else None,
                    'mail': str(entry.mail) if hasattr(entry, 'mail') else None,
                    'displayName': str(entry.displayName) if hasattr(entry, 'displayName') else None,
                    'altSecurityIdentities': list(entry.altSecurityIdentities) if hasattr(entry, 'altSecurityIdentities') else []
                }
            
            return None
            
        except Exception as e:
            logger.exception(f"Error getting user info: {e}")
            return None
    
    def close(self):
        """Close LDAP connection."""
        if self._conn:
            self._conn.unbind()
            self._conn = None
            logger.info("LDAP connection closed")
