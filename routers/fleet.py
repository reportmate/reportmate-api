"""Fleet-wide bulk data endpoints for analytics dashboards."""

import json
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from dependencies import (
    cache_get, cache_set, get_db_connection, load_sql, logger,
    normalize_app_name, paginate, verify_authentication,
    build_os_summary, infer_platform,
)

router = APIRouter(tags=["fleet"])

@router.get("/devices/applications/filters", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_applications_filters(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Lightweight endpoint for application filter options.
    
    Returns unique application names, publishers, categories, and inventory
    filter values using SQL DISTINCT queries — without downloading all records.
    Also returns a lightweight device list (serial, name, inventory fields)
    for the "missing" report mode.
    
    This replaces the pattern of calling /api/devices/applications?loadAll=true
    and processing 200K+ records client-side.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("applications_filters", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Fetching applications filter options (includeArchived={include_archived})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Extract unique app names, publishers, categories via JSONB unnesting
        options_query = load_sql("devices/applications_filter_options")
        cursor.execute(options_query, {"include_archived": include_archived})
        option_rows = cursor.fetchall()
        
        app_names = set()
        windows_app_names = set()
        mac_app_names = set()
        publishers = set()
        categories = set()
        
        for app_name, publisher, category, platform in option_rows:
            if app_name and app_name.strip():
                app_names.add(app_name.strip())
                if platform in ('Windows NT', 'Windows'):
                    windows_app_names.add(app_name.strip())
                elif platform in ('Darwin', 'macOS'):
                    mac_app_names.add(app_name.strip())
            if publisher and publisher.strip():
                publishers.add(publisher.strip())
            if category and category.strip():
                categories.add(category.strip())
        
        # 2. Get lightweight device list with inventory metadata
        devices_query = load_sql("devices/applications_filter_devices")
        cursor.execute(devices_query, {"include_archived": include_archived})
        device_rows = cursor.fetchall()
        
        conn.close()
        
        usages = set()
        catalogs = set()
        locations = set()
        devices = []
        
        for serial, device_name, usage, catalog, location in device_rows:
            devices.append({
                'serialNumber': serial,
                'name': device_name or serial,
                'usage': usage or '',
                'catalog': catalog or '',
                'location': location or '',
                'room': location or ''
            })
            if usage:
                usages.add(usage)
            if catalog:
                catalogs.add(catalog)
            if location:
                locations.add(location)
        
        logger.info(f"Applications filters: {len(app_names)} unique apps, {len(publishers)} publishers, {len(devices)} devices")
        
        _result = {
            'applicationNames': sorted(app_names),
            'windowsApplicationNames': sorted(windows_app_names),
            'macApplicationNames': sorted(mac_app_names),
            'publishers': sorted(publishers),
            'categories': sorted(categories),
            'usages': sorted(usages),
            'catalogs': sorted(catalogs),
            'locations': sorted(locations),
            'rooms': sorted(locations),
            'fleets': [],
            'devices': devices,
            'devicesWithData': len(devices)
        }
        cache_set("applications_filters", _result, _ckey)
        logger.info(f"[PERF] /api/devices/applications/filters: {_time.monotonic()-_t0:.3f}s")
        return _result
        
    except Exception as e:
        logger.error(f"Failed to get applications filters: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve applications filters: {str(e)}")


@router.get("/devices/applications", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_applications(
    request: Request,
    deviceNames: Optional[str] = None,
    applicationNames: Optional[str] = None,
    publishers: Optional[str] = None,
    categories: Optional[str] = None,
    versions: Optional[str] = None,
    search: Optional[str] = None,
    installDateFrom: Optional[str] = None,
    installDateTo: Optional[str] = None,
    sizeMin: Optional[int] = None,
    sizeMax: Optional[int] = None,
    loadAll: bool = False,
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk applications endpoint with filtering support.
    
    Returns flattened list of applications across all devices with filtering.
    Frontend is responsible for search/filtering logic - this is just data retrieval.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    conn = None
    try:
        _ckey = (str(dict(sorted(request.query_params.items()))),)
        _cached = cache_get("applications", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info(f"Fetching bulk applications (loadAll={loadAll}, includeArchived={include_archived}, filters={dict(request.query_params)})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse comma-separated filter values
        device_name_list = deviceNames.split(',') if deviceNames else []
        app_name_list = applicationNames.split(',') if applicationNames else []
        publisher_list = publishers.split(',') if publishers else []
        category_list = categories.split(',') if categories else []
        version_list = versions.split(',') if versions else []
        
        # Build WHERE clause for device filtering (including archive filter)
        where_conditions = [
            "d.serial_number IS NOT NULL", 
            "d.serial_number NOT LIKE 'TEST-%'", 
            "d.serial_number != 'localhost'"
        ]
        
        # Add archive filter
        if not include_archived:
            where_conditions.append("d.archived = FALSE")
        
        query_params = []
        param_index = 1
        
        if device_name_list:
            placeholders = ', '.join([f'${i}' for i in range(param_index, param_index + len(device_name_list) * 3)])
            where_conditions.append(f"(COALESCE(inv.data->>'device_name', inv.data->>'deviceName') IN ({placeholders}) OR COALESCE(inv.data->>'computer_name', inv.data->>'computerName') IN ({placeholders}) OR d.serial_number IN ({placeholders}))")
            query_params.extend(device_name_list * 3)
            param_index += len(device_name_list) * 3
        
        where_clause = ' AND '.join(where_conditions)
        
        # Query to get all devices with applications data
        query = f"""
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            a.data as applications_data,
            a.collected_at,
            COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
            COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
            COALESCE(sys.data->'operatingSystem'->>'name', d.platform) as platform
        FROM devices d
        LEFT JOIN applications a ON d.id = a.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        LEFT JOIN system sys ON d.id = sys.device_id
        WHERE {where_clause}
            AND a.data IS NOT NULL
        ORDER BY d.serial_number, a.updated_at DESC
        """
        
        cursor.execute(query, tuple(query_params))
        rows = cursor.fetchall()
        conn.close()
        conn = None
        
        logger.info(f"Retrieved {len(rows)} devices with applications data")
        
        # Process and flatten applications - process one device at a time
        # to limit peak memory (each device's apps_data is released after processing)
        all_applications = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, apps_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, platform = row
                
                device_display_name = device_name or computer_name or serial_number
                
                if not apps_data:
                    continue
                
                # Handle different data structures
                installed_apps = []
                if isinstance(apps_data, dict):
                    installed_apps = apps_data.get('installedApplications') or apps_data.get('InstalledApplications') or apps_data.get('installed_applications') or []
                elif isinstance(apps_data, list):
                    installed_apps = apps_data
                
                last_seen_iso = last_seen.isoformat() if last_seen else None
                collected_at_iso = collected_at.isoformat() if collected_at else None
                
                # Flatten each application - only extract needed fields (no raw copy)
                for idx, app in enumerate(installed_apps):
                    app_name = app.get('name') or app.get('displayName') or 'Unknown Application'
                    app_publisher = app.get('publisher') or app.get('signed_by') or app.get('vendor') or 'Unknown'
                    app_category = app.get('category', 'Other')
                    app_version = app.get('version') or app.get('bundle_version') or 'Unknown'
                    app_size = app.get('size') or app.get('estimatedSize')
                    app_install_date = app.get('installDate') or app.get('install_date') or app.get('last_modified')
                    
                    # Apply application-level filters
                    if app_name_list and not any(name.lower() in app_name.lower() for name in app_name_list):
                        continue
                    if publisher_list and not any(pub.lower() in app_publisher.lower() for pub in publisher_list):
                        continue
                    if category_list and app_category not in category_list:
                        continue
                    if version_list and app_version not in version_list:
                        continue
                    if search and search.lower() not in app_name.lower():
                        continue
                    if sizeMin and app_size and app_size < sizeMin:
                        continue
                    if sizeMax and app_size and app_size > sizeMax:
                        continue
                    
                    all_applications.append({
                        'id': f"{device_uuid}_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen_iso,
                        'collectedAt': collected_at_iso,
                        'name': app_name,
                        'version': app_version,
                        'vendor': app_publisher,
                        'publisher': app_publisher,
                        'category': app_category,
                        'installDate': app_install_date,
                        'size': app_size,
                        'path': app.get('path') or app.get('install_location'),
                        'architecture': app.get('architecture', 'Unknown'),
                        'bundleId': app.get('bundleId') or app.get('bundle_id'),
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'platform': platform
                    })
            
            except Exception as e:
                logger.warning(f"Error processing applications for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_applications)} applications from {len(rows)} devices")
        cache_set("applications", all_applications, _ckey)
        logger.info(f"[PERF] /api/devices/applications: {_time.monotonic()-_t0:.3f}s ({len(all_applications)} apps)")
        return paginate(all_applications, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk applications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk applications: {str(e)}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@router.get("/devices/hardware", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_hardware(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk hardware endpoint.
    
    Returns flattened list of hardware details across all devices.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers (serial number, device ID, name)
    - Hardware specs (manufacturer, model, CPU, memory, storage, GPU)
    - OS information (name, version, architecture)
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("hardware", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk hardware data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_hardware")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with hardware data")
        
        # Process hardware data
        all_hardware = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, hardware_data, collected_at, system_data, device_name, computer_name = row
                
                device_display_name = device_name or computer_name or serial_number
                
                # Extract OS info from system data
                os_info = {}
                if system_data:
                    if isinstance(system_data, list) and len(system_data) > 0:
                        os_info = system_data[0].get('operatingSystem', {})
                    elif isinstance(system_data, dict):
                        os_info = system_data.get('operatingSystem', {})
                
                # Extract hardware details
                hw_details = hardware_data if isinstance(hardware_data, dict) else {}
                
                # Pre-extract fields the frontend needs (eliminates raw blob)
                processor_data = hw_details.get('processor') or hw_details.get('cpu')
                memory_data = hw_details.get('memory') or hw_details.get('totalMemory') or hw_details.get('physicalMemory')
                graphics_data = hw_details.get('graphics') or hw_details.get('gpu') or hw_details.get('displayAdapter')
                storage_data = hw_details.get('storage') or hw_details.get('drives')
                
                # Slim storage to summary only (removes rootDirectories tree which is ~40KB per device)
                slim_storage = None
                if storage_data:
                    if isinstance(storage_data, list):
                        slim_storage = [{
                            'name': d.get('name'),
                            'type': d.get('type'),
                            'capacity': d.get('capacity') or d.get('size'),
                            'freeSpace': d.get('freeSpace') or d.get('free_space'),
                            'health': d.get('health'),
                            'interface': d.get('interface'),
                            'isInternal': d.get('isInternal'),
                        } for d in storage_data]
                    elif isinstance(storage_data, dict):
                        slim_storage = storage_data
                
                # Slim processor to summary fields only
                slim_processor = processor_data
                if isinstance(processor_data, dict):
                    slim_processor = {
                        'name': processor_data.get('name') or processor_data.get('model') or processor_data.get('brand'),
                        'cores': processor_data.get('cores') or processor_data.get('core_count') or processor_data.get('logicalCores'),
                        'speed': processor_data.get('speed') or processor_data.get('frequency') or processor_data.get('currentSpeed'),
                        'architecture': processor_data.get('architecture'),
                    }
                
                all_hardware.append({
                    'serialNumber': serial_number,
                    'deviceId': device_uuid,
                    'deviceName': device_display_name,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'manufacturer': hw_details.get('manufacturer') or hw_details.get('systemManufacturer'),
                    'model': hw_details.get('model') or hw_details.get('systemProductName'),
                    'processor': slim_processor,
                    'memory': memory_data,
                    'storage': slim_storage,
                    'graphics': graphics_data,
                    'osName': os_info.get('name'),
                    'osVersion': os_info.get('version') or os_info.get('displayVersion'),
                    'architecture': os_info.get('architecture'),
                    'inventory': hw_details.get('inventory', {}),
                    'assetTag': (hw_details.get('inventory') or {}).get('assetTag') or (hw_details.get('inventory') or {}).get('asset_tag'),
                })
            
            except Exception as e:
                logger.warning(f"Error processing hardware for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_hardware)} hardware records")
        cache_set("hardware", all_hardware, _ckey)
        logger.info(f"[PERF] /api/devices/hardware: {_time.monotonic()-_t0:.3f}s ({len(all_hardware)} devices)")
        return paginate(all_hardware, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk hardware: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk hardware: {str(e)}")


@router.get("/devices/installs/filters", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_installs_filters(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Lightweight endpoint for installs filter options.
    
    Returns unique managed install names, inventory filter values, config metadata,
    and a lightweight device list with pre-computed status counts.
    
    This replaces downloading the full /api/devices/installs/full (52MB+) just
    to extract filter options client-side.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs_filters", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Fetching installs filter options (includeArchived={include_archived})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = load_sql("devices/installs_filter_options")
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        managed_installs = set()
        cimian_installs = set()
        munki_installs = set()
        usages = set()
        catalogs = set()
        rooms = set()
        fleets = set()
        platforms = set()
        software_repos = set()
        manifests = set()
        devices = []
        
        for row in rows:
            serial, device_name, usage, catalog, location, asset_tag, fleet, platform, installs_data, last_seen = row
            
            if usage:
                usages.add(usage)
            if catalog:
                catalogs.add(catalog)
            if location:
                rooms.add(location)
            if fleet:
                fleets.add(fleet)
            if platform:
                normalized_platform = 'Macintosh' if platform == 'Darwin' else 'Windows' if platform == 'Windows NT' else platform
                platforms.add(normalized_platform)
            
            installs_obj = installs_data if isinstance(installs_data, dict) else {}
            cimian_data = installs_obj.get('cimian', {})
            munki_data = installs_obj.get('munki', {})
            
            # Extract unique item names
            for item in cimian_data.get('items', []):
                name = item.get('itemName') or item.get('displayName')
                if name and name not in ('managed_apps', 'managed_profiles'):
                    managed_installs.add(name.strip())
                    cimian_installs.add(name.strip())
            
            for item in munki_data.get('items', []):
                name = item.get('name') or item.get('displayName')
                if name:
                    managed_installs.add(name.strip())
                    munki_installs.add(name.strip())
            
            # Extract config metadata
            config = cimian_data.get('config', {})
            if config.get('SoftwareRepoURL'):
                software_repos.add(config['SoftwareRepoURL'])
            if config.get('softwareRepoUrl'):
                software_repos.add(config['softwareRepoUrl'])
            if config.get('ClientIdentifier'):
                manifests.add(config['ClientIdentifier'])
            if config.get('clientIdentifier'):
                manifests.add(config['clientIdentifier'])
            
            munki_repo = munki_data.get('softwareRepoURL')
            if munki_repo:
                software_repos.add(munki_repo)
            munki_client = munki_data.get('clientIdentifier')
            if munki_client:
                manifests.add(munki_client)
            
            # Pre-compute item status counts
            items = cimian_data.get('items', []) or munki_data.get('items', [])
            installed_count = 0
            pending_count = 0
            error_count = 0
            warning_count = 0
            removed_count = 0
            
            for item in items:
                status = (item.get('currentStatus') or item.get('status') or '').lower()
                if status in ('installed', 'install-of-', 'install_of', 'present'):
                    installed_count += 1
                elif status in ('will-be-installed', 'will_be_installed', 'pending', 'downloading', 'installing'):
                    pending_count += 1
                elif status in ('install-failed', 'install_failed', 'error', 'failed'):
                    error_count += 1
                elif status in ('warning', 'needs-update', 'needs_update'):
                    warning_count += 1
                elif status in ('removed', 'will-be-removed', 'will_be_removed', 'removal-of-'):
                    removed_count += 1
                else:
                    installed_count += 1  # Default to installed
            
            # Determine config type
            is_cimian = bool(cimian_data)
            config_type = 'Cimian' if is_cimian else ('Munki' if munki_data else 'None')
            
            # Get most recent session
            sessions = cimian_data.get('sessions', []) or munki_data.get('sessions', [])
            latest_session = sessions[0] if sessions else None
            
            # Build device record with slimmed items — keep only fields the frontend needs
            # for status categorization, error/warning widgets, and drill-down tables.
            # Drops: type, category, developer, updateCount, failureCount, installCount,
            # mappedStatus, warningCount, installMethod, pendingReason, totalSessions,
            # hasInstallLoop, recentAttempts, lastAttemptStatus, lastSeenInSession, installLoopDetected
            ITEM_KEEP_FIELDS = ('id', 'itemName', 'displayName', 'name', 'itemType',
                                'currentStatus', 'status', 'lastError', 'lastWarning',
                                'latestVersion', 'installedVersion', 'lastUpdate', 'lastAttemptTime')
            
            cimian_slim = None
            if cimian_data:
                slim_items = [
                    {k: item.get(k) for k in ITEM_KEEP_FIELDS if item.get(k) is not None and item.get(k) != ''}
                    for item in cimian_data.get('items', [])
                ]
                cimian_slim = {
                    'config': config,
                    'version': cimian_data.get('version'),
                    'status': cimian_data.get('status'),
                    'sessions': (cimian_data.get('sessions') or [])[:5],
                    'items': slim_items,
                    'itemCounts': {
                        'total': len(cimian_data.get('items', [])),
                        'installed': installed_count,
                        'pending': pending_count,
                        'error': error_count,
                        'warning': warning_count,
                        'removed': removed_count,
                    }
                }
            
            munki_slim = None
            if munki_data:
                slim_munki_items = [
                    {k: item.get(k) for k in ITEM_KEEP_FIELDS if item.get(k) is not None and item.get(k) != ''}
                    for item in munki_data.get('items', [])
                ]
                munki_slim = {
                    'version': munki_data.get('version'),
                    'status': munki_data.get('status'),
                    'manifestName': munki_data.get('manifestName'),
                    'clientIdentifier': munki_data.get('clientIdentifier'),
                    'softwareRepoURL': munki_data.get('softwareRepoURL'),
                    'lastRunSuccess': munki_data.get('lastRunSuccess'),
                    'items': slim_munki_items,
                    'itemCounts': {
                        'total': len(munki_data.get('items', [])),
                        'installed': installed_count,
                        'pending': pending_count,
                        'error': error_count,
                        'warning': warning_count,
                        'removed': removed_count,
                    }
                }
            
            devices.append({
                'serialNumber': serial,
                'deviceName': device_name or serial,
                'deviceId': None,
                'lastSeen': last_seen.isoformat() if last_seen else None,
                'platform': platform,
                'modules': {
                    'installs': {
                        'cimian': cimian_slim,
                        'munki': munki_slim,
                    },
                    'inventory': {
                        'deviceName': device_name,
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'fleet': fleet,
                    }
                }
            })
        
        logger.info(f"Installs filters: {len(managed_installs)} unique installs, {len(devices)} devices")
        
        _result = {
            'success': True,
            'managedInstalls': sorted(managed_installs),
            'cimianInstalls': sorted(cimian_installs),
            'munkiInstalls': sorted(munki_installs),
            'otherInstalls': [],
            'usages': sorted(usages),
            'catalogs': sorted(catalogs),
            'rooms': sorted(rooms),
            'fleets': sorted(fleets),
            'platforms': sorted(platforms),
            'softwareRepos': sorted(software_repos),
            'manifests': sorted(manifests),
            'devicesWithData': len(devices),
            'devices': devices
        }
        cache_set("installs_filters", _result, _ckey)
        logger.info(f"[PERF] /api/devices/installs/filters: {_time.monotonic()-_t0:.3f}s")
        return _result
        
    except Exception as e:
        logger.error(f"Failed to get installs filters: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve installs filters: {str(e)}")


@router.get("/devices/installs", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_installs(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk installs endpoint for Cimian managed packages.
    
    Returns flattened list of managed installs across all devices.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory data
    - Cimian package status (item name, version, update status)
    - Install dates and last check timestamps
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk installs data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_installs")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with installs data")
        
        # Process installs data
        all_installs = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, installs_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, fleet, platform = row
                
                device_display_name = device_name or computer_name or serial_number
                
                # Extract Cimian data (Windows)
                cimian_data = installs_data.get('cimian', {}) if isinstance(installs_data, dict) else {}
                cimian_items = cimian_data.get('items', [])
                
                # Extract Munki data (macOS)
                munki_data = installs_data.get('munki', {}) if isinstance(installs_data, dict) else {}
                munki_items = munki_data.get('items', [])
                
                # Flatten Cimian installs
                for idx, item in enumerate(cimian_items):
                    all_installs.append({
                        'id': f"{device_uuid}_cimian_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen.isoformat() if last_seen else None,
                        'collectedAt': collected_at.isoformat() if collected_at else None,
                        'itemName': item.get('itemName'),
                        'currentStatus': item.get('currentStatus'),
                        'latestVersion': item.get('latestVersion'),
                        'installedVersion': item.get('installedVersion'),
                        'installDate': item.get('installDate'),
                        'lastChecked': item.get('lastChecked'),
                        'updateAvailable': item.get('updateAvailable'),
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'fleet': fleet,
                        'platform': platform or 'Windows',
                        'source': 'cimian'
                    })
                
                # Flatten Munki installs (macOS)
                for idx, item in enumerate(munki_items):
                    all_installs.append({
                        'id': f"{device_uuid}_munki_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen.isoformat() if last_seen else None,
                        'collectedAt': collected_at.isoformat() if collected_at else None,
                        'itemName': item.get('name') or item.get('displayName'),
                        'currentStatus': item.get('status'),
                        'latestVersion': item.get('version'),
                        'installedVersion': item.get('installedVersion'),
                        'installDate': item.get('endTime'),
                        'lastChecked': None,
                        'updateAvailable': None,
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'fleet': fleet,
                        'platform': platform or 'macOS',
                        'source': 'munki'
                    })
            
            except Exception as e:
                logger.warning(f"Error processing installs for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_installs)} install records from {len(rows)} devices")
        cache_set("installs", all_installs, _ckey)
        logger.info(f"[PERF] /api/devices/installs: {_time.monotonic()-_t0:.3f}s ({len(all_installs)} records)")
        return paginate(all_installs, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")



@router.get("/devices/installs/full", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_installs_full(
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk installs endpoint returning FULL device records with nested structure.
    
    Unlike /api/devices/installs (flat items), this returns devices with complete
    modules.installs structure including config, version, sessions etc.
    Used by /devices/installs page for full UI rendering.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs_full", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk installs (full structure)")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # PERFORMANCE: Same query structure as working flat endpoint
        # Use d.id = i.device_id which is how installs are stored
        query = """
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            i.data as installs_data,
            COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag
        FROM devices d
        LEFT JOIN installs i ON d.id = i.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        WHERE d.serial_number IS NOT NULL
            AND d.serial_number NOT LIKE 'TEST-%'
            AND i.data IS NOT NULL
        """
        
        # Add archive filter
        if not include_archived:
            query += " AND d.archived = FALSE"
        
        query += " ORDER BY d.serial_number, i.updated_at DESC"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with full installs data")
        
        # Build full device records with nested structure
        devices = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, installs_data, device_name, usage, catalog, location, asset_tag = row
                
                # Extract only what UI needs from installs_data
                installs_obj = installs_data if isinstance(installs_data, dict) else {}
                cimian_data = installs_obj.get('cimian', {})
                munki_data = installs_obj.get('munki', {})
                
                # Build lightweight installs structure (exclude runLog which is huge)
                lightweight_installs = {}
                
                # Include Cimian data if present (Windows)
                if cimian_data:
                    lightweight_installs['cimian'] = {
                        'items': cimian_data.get('items', []),
                        'config': cimian_data.get('config', {}),
                        'version': cimian_data.get('version'),
                        'status': cimian_data.get('status'),
                        'sessions': cimian_data.get('sessions', [])[:5],  # Only last 5 sessions
                    }
                
                # Include Munki data if present (macOS)
                if munki_data:
                    lightweight_installs['munki'] = {
                        'items': munki_data.get('items', []),
                        'version': munki_data.get('version'),
                        'status': munki_data.get('status'),
                        'manifestName': munki_data.get('manifestName'),
                        'clientIdentifier': munki_data.get('clientIdentifier'),
                        'softwareRepoURL': munki_data.get('softwareRepoURL'),
                        'lastRunSuccess': munki_data.get('lastRunSuccess'),
                        'startTime': munki_data.get('startTime'),
                        'endTime': munki_data.get('endTime'),
                    }
                
                devices.append({
                    'serialNumber': serial_number,
                    'deviceId': device_uuid,
                    'deviceName': device_name or serial_number,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'platform': None,
                    'modules': {
                        'installs': lightweight_installs,
                        'inventory': {
                            'deviceName': device_name,
                            'usage': usage,
                            'catalog': catalog,
                            'location': location,
                            'assetTag': asset_tag
                        }
                    }
                })
            
            except Exception as e:
                logger.warning(f"Error processing full installs for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with full installs structure")
        cache_set("installs_full", devices, _ckey)
        logger.info(f"[PERF] /api/devices/installs/full: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs (full): {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")


@router.get("/devices/network", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_network(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk network endpoint for fleet-wide network overview.
    
    Returns devices with network configuration data (interfaces, IPs, MACs, DNS, etc.).
    Used by /devices/network page for fleet-wide network visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - Network interfaces, IP addresses, MAC addresses
    - DNS configuration, gateways, and network type
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("network", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk network data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_network")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with network data")
        
        # Process devices with network info
        devices = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, network_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, os_name, os_version, build_number, uptime, boot_time = row
                
                device_obj = {
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'operatingSystem': os_name,
                    'osVersion': os_version,
                    'buildNumber': build_number,
                    'uptime': uptime,
                    'bootTime': boot_time,
                    'raw': network_data  # Raw network data for extractNetwork()
                }
                
                devices.append(device_obj)
            
            except Exception as e:
                logger.warning(f"Error processing network for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with network data")
        cache_set("network", devices, _ckey)
        logger.info(f"[PERF] /api/devices/network: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk network: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk network: {str(e)}")

@router.get("/devices/security", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_security(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk security endpoint for fleet-wide security overview.
    
    Returns devices with security configuration (TPM, BitLocker, EDR, AV, etc.).
    Used by /devices/security page for fleet-wide security visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - TPM status, BitLocker encryption state
    - EDR/AV status and configuration
    - Firewall and security baseline compliance
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("security", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk security data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_security")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with security data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, platform, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 firewall_enabled, encryption_enabled,
                 antivirus_name, antivirus_enabled, antivirus_up_to_date, antivirus_version, antivirus_last_scan,
                 detection_count,
                 tpm_present, tpm_enabled, secure_boot_enabled, secure_boot_db_cert_count, secure_boot_kek_cert_count, sip_enabled, gatekeeper_enabled,
                 memory_integrity_enabled, core_isolation_enabled, smart_app_control_state,
                 ssh_status_display, ssh_is_configured, ssh_is_service_running, rdp_enabled,
                 certificate_count, expired_cert_count, expiring_soon_cert_count,
                 cve_count, critical_cve_count,
                 auto_login_user) = row
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'platform': platform,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    # Firewall
                    'firewallEnabled': bool(firewall_enabled),
                    # Encryption
                    'encryptionEnabled': bool(encryption_enabled),
                    # Antivirus / Protection
                    'antivirusName': antivirus_name or '',
                    'antivirusEnabled': bool(antivirus_enabled),
                    'antivirusUpToDate': bool(antivirus_up_to_date),
                    'antivirusVersion': antivirus_version,
                    'antivirusLastScan': antivirus_last_scan,
                    # Detection (threat alerts count - 0 = clean)
                    'detectionCount': int(detection_count or 0),
                    # Tampering
                    'tpmPresent': bool(tpm_present),
                    'tpmEnabled': bool(tpm_enabled),
                    'secureBootEnabled': bool(secure_boot_enabled),
                    'secureBootDbCertCount': int(secure_boot_db_cert_count or 0),
                    'secureBootKekCertCount': int(secure_boot_kek_cert_count or 0),
                    'sipEnabled': sip_enabled,
                    'gatekeeperEnabled': bool(gatekeeper_enabled),
                    # Protection (Windows)
                    'memoryIntegrityEnabled': bool(memory_integrity_enabled),
                    'coreIsolationEnabled': bool(core_isolation_enabled),
                    'smartAppControlState': smart_app_control_state,
                    # Remote Access
                    'secureShell': {
                        'statusDisplay': ssh_status_display,
                        'isConfigured': bool(ssh_is_configured),
                        'isServiceRunning': bool(ssh_is_service_running),
                    },
                    'rdpEnabled': bool(rdp_enabled),
                    # Certificates
                    'certificateCount': certificate_count or 0,
                    'expiredCertCount': expired_cert_count or 0,
                    'expiringSoonCertCount': expiring_soon_cert_count or 0,
                    # Vulnerabilities
                    'cveCount': cve_count or 0,
                    'criticalCveCount': critical_cve_count or 0,
                    # Misc
                    'autoLoginUser': auto_login_user,
                })
            except Exception as e:
                logger.warning(f"Error processing security for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with security data")
        cache_set("security", devices, _ckey)
        logger.info(f"[PERF] /api/devices/security: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk security: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk security: {str(e)}")

@router.get("/devices/security/certificates", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def search_fleet_certificates(
    search: str = Query(default="", description="Search term to match against certificate commonName, issuer, subject, or serialNumber"),
    status: str = Query(default="all", description="Filter by certificate status: all, valid, expired, expiring"),
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
):
    """
    Fleet-wide certificate search endpoint.
    
    Searches across all device certificates for matching commonName, issuer, subject, or serialNumber.
    Useful for verifying certificate deployment across the fleet or finding expired certificates.
    
    **Parameters:**
    - search: Text to search for (case-insensitive, partial match)
    - status: Filter by cert status (all, valid, expired, expiring)
    - includeArchived: Include archived devices
    """
    try:
        _ckey = (search.strip(), status.strip().lower(), include_archived)
        _cached = cache_get("security_certs", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Searching fleet certificates: search='{search}', status='{status}'")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = load_sql("devices/security_certificates")
        
        cursor.execute(query, {
            "search": search.strip(),
            "status": status.strip().lower(),
            "include_archived": include_archived
        })
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Certificate search returned {len(rows)} results")
        
        results = []
        for row in rows:
            try:
                (serial_number, platform, device_name,
                 common_name, issuer, subject, cert_status,
                 not_after, not_before, days_until_expiry,
                 is_expired, is_expiring_soon,
                 store_name, store_location, key_algorithm,
                 cert_serial_number, is_self_signed) = row
                
                results.append({
                    'serialNumber': serial_number,
                    'platform': platform,
                    'deviceName': device_name,
                    'commonName': common_name,
                    'issuer': issuer,
                    'subject': subject,
                    'status': cert_status,
                    'notAfter': not_after,
                    'notBefore': not_before,
                    'daysUntilExpiry': days_until_expiry,
                    'isExpired': bool(is_expired),
                    'isExpiringSoon': bool(is_expiring_soon),
                    'storeName': store_name,
                    'storeLocation': store_location,
                    'keyAlgorithm': key_algorithm,
                    'certSerialNumber': cert_serial_number,
                    'isSelfSigned': bool(is_self_signed),
                })
            except Exception as e:
                logger.warning(f"Error processing certificate row: {e}")
                continue
        
        cache_set("security_certs", results, _ckey)
        logger.info(f"[PERF] /api/devices/security/certificates: {_time.monotonic()-_t0:.3f}s ({len(results)} certs)")
        return results
        
    except Exception as e:
        logger.error(f"Failed to search fleet certificates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to search certificates: {str(e)}")

@router.get("/devices/management", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_management(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk management endpoint for fleet-wide MDM status.
    
    Returns devices with MDM enrollment status and management configuration.
    Used by /devices/management page for fleet-wide MDM visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - MDM enrollment status (Enrolled/Not Enrolled)
    - Provider, enrollment type, Intune ID
    - Tenant information
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("management", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk management data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_management")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with management data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, management_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department = row
                
                # Extract key management fields from the raw data for easy frontend access
                # Support both Windows (camelCase) and Mac (snake_case) field names
                mdm_enrollment = management_data.get('mdmEnrollment', {}) or management_data.get('mdm_enrollment', {}) if management_data else {}
                device_details = management_data.get('deviceDetails', {}) or management_data.get('device_details', {}) if management_data else {}
                tenant_details = management_data.get('tenantDetails', {}) or management_data.get('tenant_details', {}) if management_data else {}
                mdm_certificate_raw = management_data.get('mdmCertificate', {}) or management_data.get('mdm_certificate', {}) if management_data else {}
                
                # Parse MDM certificate - Mac osquery returns JSON in 'output' field
                mdm_certificate = {}
                if mdm_certificate_raw:
                    if 'output' in mdm_certificate_raw and isinstance(mdm_certificate_raw['output'], str):
                        try:
                            import json
                            # Clean up osquery's escaped JSON format
                            clean_json = mdm_certificate_raw['output'].replace(';"', '"').strip()
                            mdm_certificate = json.loads(clean_json)
                        except:
                            mdm_certificate = mdm_certificate_raw
                    else:
                        mdm_certificate = mdm_certificate_raw
                
                # Determine enrollment status - support both isEnrolled (Windows) and enrolled (Mac)
                # Mac osquery returns string "true"/"false", Windows returns boolean
                is_enrolled_raw = mdm_enrollment.get('isEnrolled') or mdm_enrollment.get('is_enrolled') or mdm_enrollment.get('enrolled')
                is_enrolled = is_enrolled_raw in (True, 'true', '1', 'yes', 'True')
                enrollment_status = 'Enrolled' if is_enrolled else 'Not Enrolled'
                
                # Provider detection - support multiple sources
                # Priority: explicit provider field > certificate issuer > "Unknown"
                provider = mdm_enrollment.get('provider')
                if not provider:
                    # Try to get from certificate data (Mac)
                    cert_issuer = mdm_certificate.get('certificate_issuer') or mdm_certificate.get('certificateIssuer')
                    cert_provider = mdm_certificate.get('mdm_provider') or mdm_certificate.get('mdmProvider')
                    if cert_provider:
                        provider = cert_provider
                    elif cert_issuer:
                        issuer_lower = cert_issuer.lower()
                        if 'micromdm' in issuer_lower:
                            provider = 'MicroMDM'
                        elif 'nanomdm' in issuer_lower:
                            provider = 'NanoMDM'
                        elif 'jamf' in issuer_lower:
                            provider = 'Jamf Pro'
                        elif 'microsoft' in issuer_lower:
                            provider = 'Microsoft Intune'
                        else:
                            provider = cert_issuer  # Use issuer as provider
                if not provider:
                    provider = 'Unknown'
                
                # Enrollment type - support Mac and Windows patterns
                enrollment_type = mdm_enrollment.get('enrollmentType') or mdm_enrollment.get('enrollment_type')
                if not enrollment_type and is_enrolled:
                    # Mac-specific: Check for DEP/ADE enrollment
                    installed_from_dep = mdm_enrollment.get('installed_from_dep') or mdm_enrollment.get('installedFromDep')
                    user_approved = mdm_enrollment.get('user_approved') or mdm_enrollment.get('userApproved')
                    if installed_from_dep in (True, 'true', '1', 'True'):
                        enrollment_type = 'Automated Device Enrollment'
                    elif user_approved in (True, 'true', '1', 'True'):
                        enrollment_type = 'User Approved Enrollment'
                    else:
                        enrollment_type = 'MDM Enrolled'
                if not enrollment_type:
                    enrollment_type = 'N/A'
                
                # Determine platform from provider
                provider_lower = (provider or '').lower()
                if provider in ('MicroMDM', 'NanoMDM', 'Apple', 'Mosyle', 'Kandji') or 'jamf' in provider_lower:
                    device_platform = 'macOS'
                elif provider == 'Microsoft Intune':
                    device_platform = 'Windows'
                else:
                    device_platform = None
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    # Extract flattened MDM fields for table display (using actual field names from data)
                    'provider': provider,
                    'enrollmentStatus': enrollment_status,
                    'enrollmentType': enrollment_type,
                    'platform': device_platform,
                    'intuneId': device_details.get('intuneDeviceId') or device_details.get('intune_device_id') or (management_data.get('device_identifiers', {}) or {}).get('uuid') or device_uuid or 'N/A',
                    'tenantName': tenant_details.get('tenantName') or tenant_details.get('tenant_name') or tenant_details.get('organization') or 'N/A',
                    'isEnrolled': is_enrolled,
                    # Pre-extracted fields (replaces raw blob)
                    'autopilotConfig': management_data.get('autopilot_config') or management_data.get('autopilotConfig') if management_data else None,
                    'osName': None  # populated below from system data if available
                })
                
                # Try to populate osName from system data via a separate query if needed
                # For now, set from management_data if system info is embedded
                if management_data:
                    sys_data = management_data.get('system', {})
                    if sys_data:
                        os_obj = sys_data.get('operatingSystem', {}) or sys_data.get('operating_system', {})
                        if os_obj:
                            devices[-1]['osName'] = os_obj.get('name')
            except Exception as e:
                logger.warning(f"Error processing management for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with management data")
        cache_set("management", devices, _ckey)
        logger.info(f"[PERF] /api/devices/management: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk management: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk management: {str(e)}")

@router.get("/devices/inventory", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_inventory(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk inventory endpoint for fleet-wide device inventory.
    
    Returns devices with inventory metadata (names, asset tags, locations, usage, etc.).
    Used by /devices/inventory page for fleet-wide inventory management.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers (serial number, device ID)
    - Asset information (name, tag, location, department)
    - Usage classification and catalog assignment
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("inventory", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk inventory data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_inventory")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with inventory data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, inventory_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department = row
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department
                })
            except Exception as e:
                logger.warning(f"Error processing inventory for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with inventory data")
        cache_set("inventory", devices, _ckey)
        logger.info(f"[PERF] /api/devices/inventory: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk inventory: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk inventory: {str(e)}")

@router.get("/devices/system", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_system(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: int = Query(default=1000, le=5000, description="Maximum number of devices to return (default 1000, max 5000)"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk system endpoint for fleet-wide OS and system information.
    
    Returns devices with OS details, uptime, updates, services, etc.
    Used by /devices/system page for fleet-wide system visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    Supports limit parameter for performance (defaults to 1000 devices, max 5000).
    
    **Response includes:**
    - Device identifiers and inventory
    - Operating system name, version, build number
    - System uptime, boot time
    - Pending updates and service status (in raw field)
    """
    try:
        _ckey = (include_archived, limit)
        _cached = cache_get("system", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info(f"Fetching bulk system data (limit: {limit})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter and limit
        query = load_sql("devices/bulk_system")
        
        cursor.execute(query, {"include_archived": include_archived, "limit": limit})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with system data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, system_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                # Extract system data (handle array format)
                if isinstance(system_data, list) and len(system_data) > 0:
                    system_data = system_data[0]
                
                # Extract operating system info from raw data (handle both snake_case and camelCase)
                os_info = system_data.get('operating_system') or system_data.get('operatingSystem', {}) if system_data else {}
                uptime_raw = system_data.get('uptime') if system_data else None
                
                # Parse uptime - handle both integer (seconds) and string (format: "d.hh:mm:ss")
                uptime_seconds = None
                if uptime_raw:
                    try:
                        # If it's already an integer, use it directly
                        if isinstance(uptime_raw, (int, float)):
                            uptime_seconds = int(uptime_raw)
                        # If it's a string, parse it
                        elif isinstance(uptime_raw, str):
                            parts = uptime_raw.replace('.', ':').split(':')
                            if len(parts) >= 4:
                                days, hours, minutes, seconds = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
                                uptime_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
                            elif len(parts) == 1:
                                # Single number as string
                                uptime_seconds = int(parts[0])
                    except (ValueError, IndexError, AttributeError) as e:
                        logger.debug(f"Could not parse uptime {uptime_raw} for device {serial_number}: {e}")
                        uptime_seconds = None
                
                # Build OS name string from components
                os_name = os_info.get('name', '')
                os_edition = os_info.get('edition', '')
                os_display_version = os_info.get('displayVersion', '')
                
                # Format: "Windows 11 Enterprise 24H2" or just the name if no edition
                operating_system = os_name
                if os_edition and os_edition not in os_name:
                    operating_system = f"{os_name} {os_edition}"
                if os_display_version:
                    operating_system = f"{operating_system} {os_display_version}"
                
                # Get counts for services, updates, scheduled_tasks (NOT the full arrays)
                services_count = 0
                updates_count = 0
                tasks_count = 0
                pending_updates_count = 0
                login_items_count = 0
                extensions_count = 0
                kernel_extensions_count = 0
                if system_data:
                    services = system_data.get('services', [])
                    updates = system_data.get('updates', [])
                    tasks = system_data.get('scheduled_tasks') or system_data.get('scheduledTasks', [])
                    services_count = len(services) if isinstance(services, list) else 0
                    updates_count = len(updates) if isinstance(updates, list) else 0
                    tasks_count = len(tasks) if isinstance(tasks, list) else 0
                    # Mac-specific counts
                    pending = system_data.get('pendingAppleUpdates') or system_data.get('pending_apple_updates', [])
                    pending_updates_count = len(pending) if isinstance(pending, list) else 0
                    deferred_updates_count = 0
                    if isinstance(pending, list):
                        deferred_updates_count = sum(1 for u in pending if isinstance(u, dict) and (u.get('deferred') or u.get('deferredUntil')))
                    # Windows pending updates from SystemModule collection
                    if pending_updates_count == 0:
                        win_count = system_data.get('pendingWindowsUpdatesCount', 0)
                        if isinstance(win_count, int) and win_count > 0:
                            pending_updates_count = win_count
                        else:
                            win_pending = system_data.get('pendingWindowsUpdates') or system_data.get('pending_windows_updates', [])
                            if isinstance(win_pending, list) and len(win_pending) > 0:
                                pending_updates_count = len(win_pending)
                    litems = system_data.get('loginItems') or system_data.get('login_items', [])
                    login_items_count = len(litems) if isinstance(litems, list) else 0
                    sext = system_data.get('systemExtensions') or system_data.get('system_extensions', [])
                    extensions_count = len(sext) if isinstance(sext, list) else 0
                    kext = system_data.get('kernelExtensions') or system_data.get('kernel_extensions', [])
                    kernel_extensions_count = len(kext) if isinstance(kext, list) else 0
                
                # Extract additional OS details already in the JSONB
                architecture = os_info.get('architecture') or os_info.get('arch', '')
                locale = os_info.get('locale', '')
                time_zone = os_info.get('timeZone') or os_info.get('time_zone', '')
                install_date = os_info.get('installDate') or os_info.get('install_date', '')
                feature_update = os_info.get('featureUpdate') or os_info.get('feature_update', '')
                uptime_string = system_data.get('uptimeString') or system_data.get('uptime_string', '') if system_data else ''
                
                # Check systemDetails for Mac locale/timezone/keyboard if not on os_info
                sys_details = system_data.get('systemDetails') or system_data.get('system_details', {}) if system_data else {}
                if not locale:
                    locale = sys_details.get('locale', '')
                if not time_zone:
                    time_zone = sys_details.get('timeZone') or sys_details.get('time_zone', '')
                
                keyboard_layouts = os_info.get('activeKeyboardLayout') or os_info.get('active_keyboard_layout', '')
                if not keyboard_layouts:
                    kb_list = os_info.get('keyboard_layouts') or os_info.get('keyboardLayouts') or sys_details.get('keyboardLayouts', [])
                    if isinstance(kb_list, list) and kb_list:
                        keyboard_layouts = ', '.join(str(k) for k in kb_list if k)
                
                # Activation details (Windows)
                activation = os_info.get('activation', {}) or {}
                activation_status = activation.get('isActivated', activation.get('is_activated'))
                license_type = activation.get('licenseType') or activation.get('license_type', '')
                license_source = activation.get('licenseSource') or activation.get('license_source', '')
                has_firmware_license = activation.get('hasFirmwareLicense', activation.get('has_firmware_license'))
                
                # Detect platform
                os_platform = os_info.get('platform', '')
                os_name_lower = (os_name or '').lower()
                if os_platform.lower() == 'darwin' or 'macos' in os_name_lower or 'mac os' in os_name_lower:
                    platform = 'macOS'
                elif 'windows' in os_name_lower:
                    platform = 'Windows'
                else:
                    platform = 'Unknown'
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'operatingSystem': operating_system.strip() or None,
                    'osVersion': os_info.get('version'),
                    'buildNumber': os_info.get('build'),
                    'uptime': uptime_seconds,
                    'uptimeString': uptime_string or None,
                    'bootTime': system_data.get('bootTime') or system_data.get('last_boot_time') if system_data else None,
                    'servicesCount': services_count,
                    'updatesCount': updates_count,
                    'tasksCount': tasks_count,
                    # New enriched fields
                    'platform': platform,
                    'architecture': architecture or None,
                    'edition': os_edition or None,
                    'displayVersion': os_display_version or None,
                    'locale': locale or None,
                    'timeZone': time_zone or None,
                    'keyboardLayout': keyboard_layouts or None,
                    'installDate': install_date or None,
                    'featureUpdate': feature_update or None,
                    'activationStatus': activation_status,
                    'licenseType': license_type or None,
                    'licenseSource': license_source or None,
                    'hasFirmwareLicense': has_firmware_license,
                    # Mac-specific counts
                    'pendingUpdatesCount': pending_updates_count,
                    'deferredUpdatesCount': deferred_updates_count,
                    'loginItemsCount': login_items_count,
                    'extensionsCount': extensions_count,
                    'kernelExtensionsCount': kernel_extensions_count,
                })
            except Exception as e:
                logger.warning(f"Error processing system for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with system data")
        cache_set("system", devices, _ckey)
        logger.info(f"[PERF] /api/devices/system: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk system: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk system: {str(e)}")

@router.get("/devices/peripherals", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_peripherals(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk peripherals endpoint for fleet-wide peripheral devices.
    
    Returns devices with connected peripherals (USB, input devices, audio, Bluetooth, cameras, etc.).
    Used by /devices/peripherals page for fleet-wide peripheral visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - USB devices (hubs, storage, peripherals)
    - Input devices (keyboards, mice, trackpads, graphics tablets)
    - Audio devices (speakers, microphones)
    - Bluetooth devices (paired and connected)
    - Cameras (built-in and external)
    - Thunderbolt devices (docks, displays, storage)
    - Printers (CUPS, network, direct-connect)
    - Scanners
    - External storage (USB drives, SD cards)
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("peripherals", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk peripherals data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_peripherals")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with peripherals data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, peripherals_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, platform = row
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'platform': platform,
                    # Pre-extracted peripheral categories (replaces raw blob)
                    'usbDevices': (peripherals_data or {}).get('usb', {}).get('usb_devices', []) if isinstance(peripherals_data, dict) else [],
                    'bluetoothDevices': (peripherals_data or {}).get('bluetooth', {}).get('bluetooth_devices', []) if isinstance(peripherals_data, dict) else [],
                    'printers': (peripherals_data or {}).get('printers', {}).get('print_queues', []) if isinstance(peripherals_data, dict) else [],
                    'cameras': (peripherals_data or {}).get('cameras', {}).get('camera_devices', []) if isinstance(peripherals_data, dict) else [],
                    'audioDevices': (peripherals_data or {}).get('audio', {}).get('audio_devices', []) if isinstance(peripherals_data, dict) else [],
                    'displayDevices': (peripherals_data or {}).get('displays', {}).get('monitors', []) if isinstance(peripherals_data, dict) else [],
                    'inputDevices': (peripherals_data or {}).get('input', {}).get('input_devices', []) if isinstance(peripherals_data, dict) else [],
                    'storageDevices': (peripherals_data or {}).get('storage', {}).get('storage_devices', []) if isinstance(peripherals_data, dict) else []
                })
            except Exception as e:
                logger.warning(f"Error processing peripherals for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with peripherals data")
        cache_set("peripherals", devices, _ckey)
        logger.info(f"[PERF] /api/devices/peripherals: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk peripherals: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk peripherals: {str(e)}")

@router.get("/devices/identity", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_identity(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk identity endpoint for fleet-wide user account and identity data.
    
    Returns devices with user accounts, groups, sessions, BTMDB health, and directory services.
    Used by /devices/identity page for fleet-wide identity visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - User accounts (local, domain, Apple ID linked)
    - User groups and memberships
    - Login sessions and history
    - BTMDB health (macOS background task management database)
    - Directory services (AD, Open Directory, LDAP)
    - Secure Token users
    - Platform SSO registration status
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("identity", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk identity data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_identity")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with identity data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, platform, identity_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department = row
                
                # Extract only the summary fields needed by the fleet page
                # Do NOT return the full raw identity blob (~50KB per device)
                summary = {}
                users_preview = []
                logged_in_usernames = []
                btmdb = {}
                secure_token = {}
                platform_sso = {}
                directory_services = {}
                domain_trust = {}
                windows_hello = {}
                
                if identity_data and isinstance(identity_data, dict):
                    users = identity_data.get('users') or identity_data.get('userAccounts') or []
                    groups = identity_data.get('groups') or identity_data.get('userGroups') or []
                    logged_in_users = identity_data.get('loggedInUsers') or []
                    btmdb = identity_data.get('btmdbHealth') or identity_data.get('btmdb_health') or {}
                    directory_services = identity_data.get('directoryServices') or identity_data.get('directory_services') or {}
                    secure_token = identity_data.get('secureToken') or identity_data.get('secure_token') or identity_data.get('secureTokenUsers') or {}
                    platform_sso = identity_data.get('platformSSOUsers') or identity_data.get('platform_sso_users') or {}
                    domain_trust = identity_data.get('domainTrust') or {}
                    windows_hello = identity_data.get('windowsHello') or {}
                    session_summary = identity_data.get('sessionSummary') or {}
                    
                    admin_count = sum(1 for u in users if isinstance(u, dict) and u.get('isAdmin')) if isinstance(users, list) else 0
                    disabled_count = sum(1 for u in users if isinstance(u, dict) and u.get('disabled')) if isinstance(users, list) else 0
                    
                    unique_logged_in = list(dict.fromkeys(
                        s.get('user') for s in logged_in_users 
                        if isinstance(s, dict) and s.get('user')
                    )) if isinstance(logged_in_users, list) else []
                    
                    summary = {
                        'totalUsers': len(users) if isinstance(users, list) else 0,
                        'adminUsers': admin_count,
                        'disabledUsers': disabled_count,
                        'groupCount': len(groups) if isinstance(groups, list) else 0,
                        'currentlyLoggedIn': len(unique_logged_in),
                    }
                    
                    # Top 5 users for preview
                    if isinstance(users, list):
                        users_preview = [
                            {
                                'username': u.get('username'),
                                'realName': u.get('realName'),
                                'isAdmin': u.get('isAdmin', False),
                                'lastLogon': u.get('lastLogon'),
                            }
                            for u in users[:5] if isinstance(u, dict)
                        ]
                    
                    logged_in_usernames = unique_logged_in[:3]
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'platform': platform,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'summary': summary,
                    'users': users_preview,
                    'loggedInUsernames': logged_in_usernames,
                    'btmdbHealth': {
                        'status': btmdb.get('status') or btmdb.get('health_status'),
                        'sizeMB': btmdb.get('sizeMB') or btmdb.get('size_mb'),
                    } if btmdb else None,
                    'secureTokenUsers': {
                        'tokenGrantedCount': len(secure_token.get('users', [])) if isinstance(secure_token, dict) and secure_token.get('users') else 0,
                        'tokenMissingCount': secure_token.get('tokenMissingCount', 0) if isinstance(secure_token, dict) else 0,
                    } if secure_token else None,
                    'platformSSOUsers': {
                        'deviceRegistered': platform_sso.get('deviceRegistered') or platform_sso.get('device_registered') or False,
                        'registeredUserCount': platform_sso.get('registeredUserCount', 0),
                    } if platform_sso else None,
                    'directoryServices': {
                        'activeDirectory': {
                            'bound': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('bound', False),
                            'domain': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('domain'),
                            'isDomainJoined': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('is_domain_joined') or (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('isDomainJoined', False),
                        },
                        'azureAd': {
                            'joined': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('is_aad_joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('isAadJoined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('is_entra_joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('isEntraJoined', False),
                            'tenantId': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenant_id') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenantId'),
                            'tenantName': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenant_name') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenantName'),
                        },
                        'ldap': {
                            'bound': (directory_services.get('ldap') or {}).get('bound', False),
                        },
                        'workgroup': directory_services.get('workgroup'),
                    } if directory_services else None,
                    'domainTrust': {
                        'trustStatus': domain_trust.get('trustStatus'),
                    } if domain_trust else None,
                    'windowsHello': {
                        'statusDisplay': windows_hello.get('statusDisplay'),
                    } if windows_hello else None,
                    'sessionSummary': {
                        'totalSessions': session_summary.get('totalSessions') or session_summary.get('total_sessions', 0),
                        'uniqueUsers': session_summary.get('uniqueUsers') or session_summary.get('unique_users', 0),
                        'avgSessionMinutes': session_summary.get('avgSessionMinutes') or session_summary.get('avg_session_minutes', 0),
                        'medianSessionMinutes': session_summary.get('medianSessionMinutes') or session_summary.get('median_session_minutes', 0),
                    } if session_summary else None,
                })
            except Exception as e:
                logger.warning(f"Error processing identity for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with identity data")
        cache_set("identity", devices, _ckey)
        logger.info(f"[PERF] /api/devices/identity: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk identity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk identity: {str(e)}")


@router.get("/devices/profiles", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_profiles(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk profiles endpoint for fleet-wide MDM profile and configuration data.
    
    Returns devices with MDM profiles, configuration profiles, and management settings.
    Used by /devices/profiles page for fleet-wide profile visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("profiles", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk profiles data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = load_sql("devices/bulk_profiles")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with profiles data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, profiles_data, profiles_collected_at, profiles_updated_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                # Extract profile summary from JSONB data
                profile_list = []
                profile_count = 0
                if profiles_data and isinstance(profiles_data, dict):
                    profile_list = profiles_data.get('profiles', profiles_data.get('configurationProfiles', []))
                    if isinstance(profile_list, list):
                        profile_count = len(profile_list)
                    else:
                        profile_list = []
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': profiles_collected_at.isoformat() if profiles_collected_at else None,
                    'updatedAt': profiles_updated_at.isoformat() if profiles_updated_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'profileCount': profile_count,
                    'profiles': profile_list[:50],  # Cap at 50 profiles per device for bulk response
                })
            except Exception as e:
                logger.warning(f"Error processing profiles for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with profiles data")
        cache_set("profiles", devices, _ckey)
        logger.info(f"[PERF] /api/devices/profiles: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk profiles: {str(e)}")
