import { ClusterChooserProps, registerClusterChooser } from '@kinvolk/headlamp-plugin/lib';

registerClusterChooser(({ clickHandler, cluster }: ClusterChooserProps) => {
  return <button onClick={clickHandler}>Our very own Chooser button. Cluster: {cluster}</button>;
});
