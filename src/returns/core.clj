(ns returns.core)

(defn suitable-permissions []
  (doto (java.security.Permissions.)
    (.add (RuntimePermission. "accessDeclaredMembers"))
    (.add (RuntimePermission. "createClassLoader"))))

(defn protection-domain [permissions]
  (java.security.ProtectionDomain.
   (java.security.CodeSource. nil
                              (cast java.security.cert.Certificate nil))
   permissions))

(defn access-control-context [domain]
  (java.security.AccessControlContext. (into-array [domain])))

(defn sandbox [thunk]
  (System/setSecurityManager (SecurityManager.))
  (java.security.AccessController/doPrivileged
   (proxy [java.security.PrivilegedAction] [] (run [] (eval thunk)))
   (access-control-context
    (protection-domain
     (suitable-permissions)))))
