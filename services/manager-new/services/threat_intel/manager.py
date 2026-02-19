"""Threat Intelligence Manager - Core IOC management."""

import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

import structlog

from services.models.db import get_db, db_session

logger = structlog.get_logger()


class ThreatIntelManager:
    """Manages Indicators of Compromise (IOCs) and threat intelligence."""

    INDICATOR_TYPES = ["ip", "domain", "hash", "url", "email", "file", "registry"]
    THREAT_LEVELS = ["critical", "high", "medium", "low", "info"]

    def __init__(self, redis_client=None):
        """Initialize threat intel manager."""
        self.redis = redis_client
        self._cache_ttl = 3600  # 1 hour cache

    async def create_ioc(
        self,
        indicator_type: str,
        value: str,
        threat_level: str = "medium",
        confidence: float = 0.5,
        source: str = "manual",
        tags: List[str] = None,
        description: str = None,
        first_seen: datetime = None,
        last_seen: datetime = None,
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Create a new IOC."""
        if indicator_type not in self.INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator type: {indicator_type}")
        if threat_level not in self.THREAT_LEVELS:
            raise ValueError(f"Invalid threat level: {threat_level}")

        now = datetime.utcnow()
        ioc_id = str(uuid.uuid4())

        with db_session() as db:
            # Check if IOC already exists
            existing = (
                db(
                    (db.threat_indicators.indicator_type == indicator_type)
                    & (db.threat_indicators.value == value)
                )
                .select()
                .first()
            )

            if existing:
                # Update existing IOC
                db(db.threat_indicators.id == existing.id).update(
                    threat_level=threat_level,
                    confidence=confidence,
                    last_seen=last_seen or now,
                    updated_at=now,
                )
                return self._ioc_to_dict(existing)

            # Create new IOC
            db.threat_indicators.insert(
                id=ioc_id,
                indicator_type=indicator_type,
                value=value,
                threat_level=threat_level,
                confidence=confidence,
                source=source,
                tags=tags or [],
                description=description,
                first_seen=first_seen or now,
                last_seen=last_seen or now,
                is_active=True,
                metadata=metadata or {},
                created_at=now,
                updated_at=now,
            )

        # Invalidate cache
        await self._invalidate_cache(indicator_type, value)

        logger.info(
            "IOC created",
            ioc_id=ioc_id,
            type=indicator_type,
            value=value[:50],
            threat_level=threat_level,
        )

        return {
            "id": ioc_id,
            "indicator_type": indicator_type,
            "value": value,
            "threat_level": threat_level,
            "confidence": confidence,
            "source": source,
            "tags": tags or [],
            "is_active": True,
            "created_at": now,
        }

    async def bulk_create_iocs(
        self,
        iocs: List[Dict[str, Any]],
        source: str = "bulk_import",
    ) -> Dict[str, Any]:
        """Bulk create IOCs."""
        created = 0
        updated = 0
        errors = []
        now = datetime.utcnow()

        with db_session() as db:
            for ioc_data in iocs:
                try:
                    indicator_type = ioc_data.get("indicator_type")
                    value = ioc_data.get("value")

                    if not indicator_type or not value:
                        errors.append(
                            {"value": value, "error": "Missing indicator_type or value"}
                        )
                        continue

                    # Check existing
                    existing = (
                        db(
                            (db.threat_indicators.indicator_type == indicator_type)
                            & (db.threat_indicators.value == value)
                        )
                        .select()
                        .first()
                    )

                    if existing:
                        db(db.threat_indicators.id == existing.id).update(
                            threat_level=ioc_data.get(
                                "threat_level", existing.threat_level
                            ),
                            confidence=ioc_data.get("confidence", existing.confidence),
                            last_seen=now,
                            updated_at=now,
                        )
                        updated += 1
                    else:
                        db.threat_indicators.insert(
                            id=str(uuid.uuid4()),
                            indicator_type=indicator_type,
                            value=value,
                            threat_level=ioc_data.get("threat_level", "medium"),
                            confidence=ioc_data.get("confidence", 0.5),
                            source=source,
                            tags=ioc_data.get("tags", []),
                            description=ioc_data.get("description"),
                            first_seen=now,
                            last_seen=now,
                            is_active=True,
                            metadata=ioc_data.get("metadata", {}),
                            created_at=now,
                            updated_at=now,
                        )
                        created += 1

                except Exception as e:
                    errors.append({"value": ioc_data.get("value"), "error": str(e)})

        logger.info(
            "Bulk IOC import completed",
            created=created,
            updated=updated,
            errors=len(errors),
        )

        return {
            "created": created,
            "updated": updated,
            "errors": errors,
            "total": len(iocs),
        }

    async def get_ioc(
        self, ioc_id: str = None, indicator_type: str = None, value: str = None
    ) -> Optional[Dict[str, Any]]:
        """Get IOC by ID or type/value combination."""
        with db_session() as db:
            if ioc_id:
                ioc = db(db.threat_indicators.id == ioc_id).select().first()
            elif indicator_type and value:
                ioc = (
                    db(
                        (db.threat_indicators.indicator_type == indicator_type)
                        & (db.threat_indicators.value == value)
                    )
                    .select()
                    .first()
                )
            else:
                return None

            if ioc:
                return self._ioc_to_dict(ioc)

        return None

    async def update_ioc(
        self,
        ioc_id: str,
        threat_level: str = None,
        confidence: float = None,
        tags: List[str] = None,
        is_active: bool = None,
        description: str = None,
    ) -> Optional[Dict[str, Any]]:
        """Update an existing IOC."""
        with db_session() as db:
            ioc = db(db.threat_indicators.id == ioc_id).select().first()

            if not ioc:
                return None

            updates = {"updated_at": datetime.utcnow()}

            if threat_level is not None:
                updates["threat_level"] = threat_level
            if confidence is not None:
                updates["confidence"] = confidence
            if tags is not None:
                updates["tags"] = tags
            if is_active is not None:
                updates["is_active"] = is_active
            if description is not None:
                updates["description"] = description

            db(db.threat_indicators.id == ioc_id).update(**updates)

            # Invalidate cache
            await self._invalidate_cache(ioc.indicator_type, ioc.value)

            return await self.get_ioc(ioc_id=ioc_id)

    async def delete_ioc(self, ioc_id: str) -> bool:
        """Delete an IOC."""
        with db_session() as db:
            ioc = db(db.threat_indicators.id == ioc_id).select().first()

            if not ioc:
                return False

            db(db.threat_indicators.id == ioc_id).delete()

            # Invalidate cache
            await self._invalidate_cache(ioc.indicator_type, ioc.value)

        logger.info("IOC deleted", ioc_id=ioc_id)
        return True

    async def lookup_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Look up an indicator, checking cache first."""
        # Check cache
        cache_key = f"ioc:{indicator_type}:{value}"
        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                import json

                return json.loads(cached)

        # Query database
        ioc = await self.get_ioc(indicator_type=indicator_type, value=value)

        if ioc and self.redis:
            # Cache result
            import json

            await self.redis.setex(
                cache_key, self._cache_ttl, json.dumps(ioc, default=str)
            )

        return ioc

    async def lookup_indicators(
        self, indicators: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Bulk lookup of indicators."""
        results = []

        for ind in indicators:
            indicator_type = ind.get("type")
            value = ind.get("value")

            if indicator_type and value:
                match = await self.lookup_indicator(indicator_type, value)
                if match:
                    results.append(
                        {
                            "indicator": ind,
                            "match": match,
                        }
                    )

        return results

    async def search_iocs(
        self,
        indicator_type: str = None,
        threat_level: str = None,
        source: str = None,
        tag: str = None,
        is_active: bool = None,
        first_seen_after: datetime = None,
        first_seen_before: datetime = None,
        value_contains: str = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Search IOCs with filtering."""
        with db_session() as db:
            query = db.threat_indicators

            if indicator_type:
                query = query(db.threat_indicators.indicator_type == indicator_type)
            if threat_level:
                query = query(db.threat_indicators.threat_level == threat_level)
            if source:
                query = query(db.threat_indicators.source == source)
            if tag:
                query = query(db.threat_indicators.tags.contains(tag))
            if is_active is not None:
                query = query(db.threat_indicators.is_active == is_active)
            if first_seen_after:
                query = query(db.threat_indicators.first_seen >= first_seen_after)
            if first_seen_before:
                query = query(db.threat_indicators.first_seen <= first_seen_before)
            if value_contains:
                query = query(db.threat_indicators.value.contains(value_contains))

            total = query.count()
            offset = (page - 1) * page_size

            iocs = query.select(
                orderby=~db.threat_indicators.created_at,
                limitby=(offset, offset + page_size),
            )

            return [self._ioc_to_dict(ioc) for ioc in iocs], total

    async def get_statistics(self) -> Dict[str, Any]:
        """Get IOC statistics."""
        with db_session() as db:
            total = db(db.threat_indicators).count()
            active = db(db.threat_indicators.is_active == True).count()

            # Count by type
            by_type = {}
            for t in self.INDICATOR_TYPES:
                by_type[t] = db(db.threat_indicators.indicator_type == t).count()

            # Count by threat level
            by_level = {}
            for level in self.THREAT_LEVELS:
                by_level[level] = db(db.threat_indicators.threat_level == level).count()

            # Recent activity
            now = datetime.utcnow()
            today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_ago = today - timedelta(days=7)

            added_today = db(db.threat_indicators.created_at >= today).count()
            added_this_week = db(db.threat_indicators.created_at >= week_ago).count()

            return {
                "total": total,
                "active": active,
                "inactive": total - active,
                "by_type": by_type,
                "by_threat_level": by_level,
                "added_today": added_today,
                "added_this_week": added_this_week,
                "timestamp": now.isoformat(),
            }

    async def _invalidate_cache(self, indicator_type: str, value: str) -> None:
        """Invalidate cache for an indicator."""
        if self.redis:
            cache_key = f"ioc:{indicator_type}:{value}"
            await self.redis.delete(cache_key)

    def _ioc_to_dict(self, ioc: Any) -> Dict[str, Any]:
        """Convert IOC row to dictionary."""
        return {
            "id": str(ioc.id),
            "indicator_type": ioc.indicator_type,
            "value": ioc.value,
            "threat_level": ioc.threat_level,
            "confidence": ioc.confidence,
            "source": ioc.source,
            "tags": ioc.tags or [],
            "description": ioc.description,
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
            "is_active": ioc.is_active,
            "metadata": ioc.metadata or {},
            "created_at": ioc.created_at,
            "updated_at": ioc.updated_at,
        }
