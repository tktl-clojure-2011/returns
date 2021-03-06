(ns returns.core)

(defn suitable-permissions []
  (doto (java.security.Permissions.)
    (.add (RuntimePermission. "accessDeclaredMembers"))))

(defn protection-domain [permissions]
  (java.security.ProtectionDomain.
   (java.security.CodeSource.
    nil
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

(defn make-user-tests [user code tests]
  (map (fn [t] `(do (ns ~(gensym user) (:use clojure.test)) ~@code ~t)) tests))

(defn read-user-file [filename]
  (read-string (slurp filename)))

(defn sanitize-leading-ns [user code]
  (let [[head & body :as n] (first code)
	m (vec n)]
    (if (= head 'ns)
      (cons (list* (assoc m 1 (gensym user))) (rest code))
      code)))

(def *bad-forms* #{'alter-var-root 'alterRoot 'intern 'eval 'catch 'load-string 'load-reader 'clojure.core/addMethod})

(defn de-fang
  "looks through the macroexpand of a form for things I don't allow"
  [form notallowed]
  (if (coll? form)
    (when (not
           (some notallowed
                 (tree-seq coll?
                           #(let [a (macroexpand %)]
                              (if (coll? a)
                                (seq a)
                                (list a)))
                           form)))
      form)
    form))
