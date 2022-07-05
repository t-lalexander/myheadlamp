import React from 'react';
import { ClusterChooserProps, ClusterChooserType } from '../components/cluster/ClusterChooser';
import { SectionBox } from '../components/common/SectionBox';
import { DetailsViewSectionProps, DetailsViewSectionType } from '../components/DetailsViewSection';
import { SidebarEntryProps } from '../components/Sidebar';
import { AppLogoProps, AppLogoType } from '../components/Sidebar/AppLogo';
import { KubeObject } from '../lib/k8s/cluster';
import { Route } from '../lib/router';
import {
  HeaderActionType,
  setAppBarAction,
  setBrandingAppLogoComponent,
  setClusterChooserButtonComponent,
  setDetailsView,
  setDetailsViewHeaderAction,
  setRoute,
  setSidebarItem,
} from '../redux/actions/actions';
import store from '../redux/stores/store';

export interface SectionFuncProps {
  title: string;
  component: (props: { resource: any }) => JSX.Element | null;
}

export type { AppLogoProps, AppLogoType };
export type { ClusterChooserProps, ClusterChooserType };
export type { SidebarEntryProps };
export type { DetailsViewSectionProps, DetailsViewSectionType };

/**
 * @deprecated please used DetailsViewSectionType and registerDetailViewSection
 */
export type sectionFunc = (resource: KubeObject) => SectionFuncProps | null | undefined;

// @todo: these might be better with a more well defined interface.
//        So that things like importing material-ui stuff,
//        tooltips and a11y stuff can be done.
//        Maybe in a ResourceAction component? That is used by Headlamp too.
// @todo: these should also have a *Props
// @todo: HeaderActionType should be deprecated.
export type DetailsViewHeaderActionType = HeaderActionType;
export type AppBarActionType = HeaderActionType;

export default class Registry {
  /**
   * @deprecated Registry.registerSidebarItem is deprecated. Please use registerSidebarItem.
   */
  registerSidebarItem(
    parentName: string | null,
    itemName: string,
    itemLabel: string,
    url: string,
    opts: Pick<SidebarEntryProps, 'useClusterURL' | 'icon'> = { useClusterURL: true }
  ) {
    console.warn('Registry.registerSidebarItem is deprecated. Please use registerSidebarItem.');
    const { useClusterURL = true, ...options } = opts;
    store.dispatch(
      setSidebarItem({
        name: itemName,
        label: itemLabel,
        url,
        parent: parentName,
        useClusterURL,
        ...options,
      })
    );
  }

  /**
   * @deprecated Registry.registerRoute is deprecated. Please use registerRoute.
   */
  registerRoute(routeSpec: Route) {
    console.warn('Registry.registerRoute is deprecated. Please use registerRoute.');
    return registerRoute(routeSpec);
  }

  /**
   * @deprecated Registry.registerDetailsViewHeaderAction is deprecated. Please use registerDetailsViewHeaderAction.
   */
  registerDetailsViewHeaderAction(actionName: string, actionFunc: HeaderActionType) {
    console.warn(
      'Registry.registerDetailsViewHeaderAction is deprecated. Please use registerDetailsViewHeaderAction.'
    );
    store.dispatch(setDetailsViewHeaderAction(actionFunc));
  }

  /**
   * @deprecated Registry.registerAppBarAction is deprecated. Please use registerAppBarAction.
   */
  registerAppBarAction(actionName: string, actionFunc: (...args: any[]) => JSX.Element | null) {
    console.warn('Registry.registerAppBarAction is deprecated. Please use registerAppBarAction.');
    return registerAppBarAction(actionFunc);
  }

  /**
   * @deprecated Registry.registerDetailsViewSection is deprecated. Please use registerDetailsViewSection.
   *
   * An old example...
   *
   * @see {@link https://github.com/kinvolk/signal-box/blob/a2bec8421fa90c07b8c9fc0635383fa9c2eb3d6e/plugins/biolatency/src/index.tsx#L348 Bio Latency Plugin}
   *
   * ```tsx
   *
   * register.registerDetailsViewSection('biolatency', resource => {
   *   if (resource?.kind === 'Node') {
   *     return {
   *       title: 'Block I/O Latency',
   *       component: () => <CustomComponent />,
   *     };
   *   }
   *   return null;
   * });
   *
   * ```
   *
   */
  registerDetailsViewSection(
    sectionName: string,
    sectionFunc: (props: { resource: any }) => SectionFuncProps | null
  ) {
    console.warn(
      'Registry.registerDetailsViewSection is deprecated. Please use registerDetailsViewSection.'
    );

    function OurComponent({ resource }: DetailsViewSectionProps) {
      const res = sectionFunc(resource);
      if (res === null) {
        return null;
      }

      return (
        <SectionBox title={sectionName}>
          <res.component resource={resource} />
        </SectionBox>
      );
    }

    return registerDetailsViewSection(OurComponent);
  }

  /**
   * @deprecated Registry.registerAppLogo is deprecated. Please use registerAppLogo.
   */
  registerAppLogo(logo: AppLogoType) {
    console.warn('Registry.registerAppLogo is deprecated. Please use registerAppLogo.');
    return registerAppLogo(logo);
  }

  /**
   * @deprecated Registry.registerClusterChooserComponent is deprecated. Please use registerClusterChooser.
   */
  registerClusterChooserComponent(component: React.ComponentType<ClusterChooserProps> | null) {
    console.warn(
      'Registry.registerClusterChooserComponent is deprecated. Please use registerClusterChooser.'
    );
    return registerClusterChooser(component);
  }
}

/**
 * Add a Sidebar Entry to the menu (on the left side of Headlamp).
 *
 * @example
 *
 * ```tsx
 * import { registerSidebarEntry } from '@kinvolk/headlamp-plugin/lib';
 * registerSidebarEntry({ parent: 'cluster', name: 'traces', label: 'Traces', url: '/traces' });
 *
 * ```
 *
 * @see {@link http://github.com/kinvolk/headlamp/plugins/examples/sidebar/ Sidebar Example}
 */
export function registerSidebarEntry({
  parent,
  name,
  label,
  url,
  useClusterURL = true,
  icon,
}: SidebarEntryProps) {
  store.dispatch(
    setSidebarItem({
      name,
      label,
      url,
      parent,
      useClusterURL,
      icon,
    })
  );
}

/**
 * Add a Route for a component.
 *
 * @param routeSpec - details of URL, highlighted sidebar and component to use.
 *
 * @example
 *
 * ```tsx
 * import { registerRoute } from '@kinvolk/headlamp-plugin/lib';
 *
 * // Add a route that will display the given component and select
 * // the "traces" sidebar item.
 * registerRoute({
 *   path: '/traces',
 *   sidebar: 'traces',
 *   component: () => <TraceList />
 * });
 * ```
 *
 * @see {@link https://github.com/kinvolk/headlamp/blob/main/frontend/src/lib/router.tsx Route examples}
 * @see {@link http://github.com/kinvolk/headlamp/plugins/examples/sidebar/ Sidebar Example}
 *
 */
export function registerRoute(routeSpec: Route) {
  store.dispatch(setRoute(routeSpec));
}

/**
 * Add a component into the details view header.
 *
 * @param headerAction - The action (link) to put in the app bar.
 *
 * @example
 *
 * ```tsx
 * import tracesIcon from '@iconify/icons-mdi/file-document-box-search-outline';
 * import { Icon } from '@iconify/react';
 * import { IconButton } from '@material-ui/core';
 * import { registerDetailsViewHeaderAction } from '@kinvolk/headlamp-plugin/lib';
 *
 * function IconAction() {
 *   return (
 *     <IconButton
 *       onClick={() => console.log("Hello from IconAction!")}
 *     >
 *       <Icon icon={tracesIcon} />
 *     </IconButton>
 *   )
 * }
 *
 * registerDetailsViewHeaderAction(IconAction);
 * ```
 */
export function registerDetailsViewHeaderAction(headerAction: DetailsViewHeaderActionType) {
  store.dispatch(setDetailsViewHeaderAction(headerAction));
}

/**
 * Add a component into the app bar (at the top of the app).
 *
 * @param headerAction - The action (link) to put in the app bar.
 *
 * @example
 *
 * ```tsx
 * import { registerAppBarAction } from '@kinvolk/headlamp-plugin/lib';
 * import { Button } from '@material-ui/core';
 *
 * function ConsoleLogger() {
 *   return (
 *     <Button
 *       onClick={() => {
 *         console.log('Hello from ConsoleLogger!')
 *       }}
 *     >
 *       Print Log
 *     </Button>
 *   );
 * }
 *
 * registerAppBarAction(ConsoleLogger);
 * ```
 */
export function registerAppBarAction(headerAction: AppBarActionType) {
  store.dispatch(setAppBarAction(headerAction));
}

/**
 * Append a component to the details view for a given resource.
 *
 * @param viewSection - The section to add on different view screens.
 *
 * @example
 *
 * ```tsx
 * import {
 *   registerDetailsViewSection,
 *   DetailsViewSectionProps
 * } from '@kinvolk/headlamp-plugin/lib';
 *
 * registerDetailsViewSection(({ resource }: DetailsViewSectionProps) => {
 *   if (resource.kind === 'Pod') {
 *     return (
 *       <SectionBox title="A very fine section title">
 *         The body of our Section for {resource.kind}
 *       </SectionBox>
 *     );
 *   }
 * });
 * ```
 *
 */
export function registerDetailsViewSection(viewSection: DetailsViewSectionType) {
  store.dispatch(setDetailsView(viewSection));
}

/**
 * Add a logo for Headlamp to use instead of the default one.
 *
 * @param logo is a React Component that takes two required props
 * `logoType` which is a constant string literal that accepts either
 * of the two values `small` or `large` depending on whether
 * the sidebar is in shrink or expanded state so that you can change your logo
 * from small to large and the other optional prop is the `themeName`
 * which is a string with two values 'light' and 'dark' base on which theme is selected.
 *
 * @example
 * ```tsx
 * import { registerAppLogo } from '@kinvolk/headlamp-plugin/lib';
 *
 * registerAppLogo(<p>my logo</p>)
 * ```
 *
 * More complete logo example in plugins/examples/change-logo:
 * @see {@link http://github.com/kinvolk/headlamp/plugins/examples/change-logo/ Change Logo Example}
 *
 */
export function registerAppLogo(logo: AppLogoType) {
  store.dispatch(setBrandingAppLogoComponent(logo));
}

/**
 * Use a custom cluster chooser button
 *
 * @param chooser is a React Component that takes one required props ```clickHandler``` which is the
 * action handler that happens when the custom chooser button component click event occurs
 *
 * @example
 * ```tsx
 * import { ClusterChooserProps, registerClusterChooser } from '@kinvolk/headlamp-plugin/lib';
 *
 * registerClusterChooser(({ clickHandler, cluster }: ClusterChooserProps) => {
 *   return <button onClick={clickHandler}>my chooser Current cluster: {cluster}</button>;
 * })
 * ```
 *
 * @see {@link http://github.com/kinvolk/headlamp/plugins/examples/clusterchooser/ Cluster Chooser example}
 *
 */
export function registerClusterChooser(chooser: ClusterChooserType) {
  store.dispatch(setClusterChooserButtonComponent(chooser));
}
