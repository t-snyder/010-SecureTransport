PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy

/bin/bash $PROTODIR/scripts/Step-01a-DeployOpenBaoMinikubeCluster.sh
/bin/bash $PROTODIR/scripts/Step-01b-DeployServersMinikubeCluster.sh
/bin/bash $PROTODIR/scripts/Step-01c-DeployServicesMinikubeCluster.sh
/bin/bash $PROTODIR/scripts/Step-02-OpenBao-InstallWithTLS.sh      
/bin/bash $PROTODIR/scripts/Step-03-OpenBao-Initialize-JoinUnseal.sh
/bin/bash $PROTODIR/scripts/Step-04-OpenBao-ConfigureCA.sh
/bin/bash $PROTODIR/scripts/Step-05-OpenBao-ConfigureAuthAndIssuers.sh
/bin/bash $PROTODIR/scripts/Step-06-DeployNatsToServers.sh
/bin/bash $PROTODIR/scripts/Step-07-DeployMetadataSvcToBaoCluster.sh
/bin/bash $PROTODIR/scripts/Step-08-DeployWatcherToServersCluster.sh
/bin/bash $PROTODIR/scripts/Step-09-DeployAuthController.sh
/bin/bash $PROTODIR/scripts/Step-10-DeployGatekeeper.sh

