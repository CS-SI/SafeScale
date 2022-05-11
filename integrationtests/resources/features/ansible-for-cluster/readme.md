safescale tenant set TestOVH@GRA5
# safescale cluster create cluster-ansible-archive-test (created)

## Tests that must fail:
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-failure-norequirements.zip
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-failure-wrong-rolename.zip
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-failure-wrong-vars.zip
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-failure-apttimeout.zip
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-vault.zip --vault-password-file [path]/wrongpwd.vault

## Tests that must succeed:
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-success.zip
safescale cluster ansible playbook cluster-ansible-archive-test [path]/playbook-vault.zip --vault-password-file [path]/pwd.vault
