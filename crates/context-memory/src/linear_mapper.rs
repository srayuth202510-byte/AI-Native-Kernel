use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ActorInstance {
    pub id: String,
    pub node_id: String,
    pub actor_type: String,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub last_heartbeat: std::time::Instant,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct IdentityMapping {
    pub external_id: String,
    pub internal_actor_id: String,
    pub mapping_type: MappingType,
    pub confidence: f32,
    pub created_at: std::time::Instant,
    pub expires_at: Option<std::time::Instant>,
    pub is_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingType {
    User,
    Service,
    Process,
    Resource,
    System,
}

pub struct IdentityMapper {
    pub mappings: HashMap<String, IdentityMapping>,  // external_id -> IdentityMapping
    pub reverse_mappings: HashMap<String, String>,   // internal_actor_id -> external_id
    pub actor_registry: HashMap<String, ActorInstance>, // internal_actor_id -> ActorInstance
    pub ttl_cache: HashMap<String, std::time::Instant>, // for temporary mappings
    pub max_mappings: usize,
}

impl IdentityMapper {
    pub fn new(max_mappings: usize) -> Self {
        Self {
            mappings: HashMap::new(),
            reverse_mappings: HashMap::new(),
            actor_registry: HashMap::new(),
            ttl_cache: HashMap::new(),
            max_mappings,
        }
    }

    pub fn map_identity(&mut self, external_id: &str, mapping_type: MappingType, actor_instance: Option<ActorInstance>) -> Result<String> {
        // Clean expired mappings
        self.clean_expired_mappings();
        
        // Check if mapping already exists
        if let Some(existing) = self.mappings.get(external_id) {
            if actor_instance.is_none() {
                return Ok(existing.internal_actor_id.clone());
            }
            
            // Update existing mapping
            if let Some(actor) = actor_instance {
                if let Some(old_actor) = self.actor_registry.get_mut(&existing.internal_actor_id) {
                    *old_actor = actor.clone();
                }
            }
            return Ok(existing.internal_actor_id.clone());
        }
        
        // Create new mapping
        let internal_id = if let Some(actor) = actor_instance {
            let actor_id = actor.id.clone();
            self.actor_registry.insert(actor_id.clone(), actor);
            actor_id
        } else {
            format!("actor-{}", Uuid::new_v4())
        };
        
        let mapping = IdentityMapping {
            external_id: external_id.to_string(),
            internal_actor_id: internal_id.clone(),
            mapping_type,
            confidence: 1.0,
            created_at: std::time::Instant::now(),
            expires_at: None,
            is_verified: false,
        };
        
        self.mappings.insert(external_id.to_string(), mapping);
        self.reverse_mappings.insert(internal_id.clone(), external_id.to_string());
        
        Ok(internal_id)
    }

    pub fn resolve_identity(&self, external_id: &str) -> Option<String> {
        self.mappings.get(external_id).map(|m| m.internal_actor_id.clone())
    }

    pub fn resolve_external_id(&self, internal_actor_id: &str) -> Option<String> {
        self.reverse_mappings.get(internal_actor_id).cloned()
    }

    pub fn get_actor(&self, actor_id: &str) -> Option<ActorInstance> {
        self.actor_registry.get(actor_id).cloned()
    }

    pub fn update_actor_heartbeat(&mut self, actor_id: &str) -> Result<()> {
        if let Some(actor) = self.actor_registry.get_mut(actor_id) {
            actor.last_heartbeat = std::time::Instant::now();
            actor.is_active = true;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Actor not found: {}", actor_id))
        }
    }

    pub fn cleanup_inactive_actors(&mut self) {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300); // 5 minutes
        
        // Remove inactive actors
        self.actor_registry.retain(|_, actor| {
            if actor.last_heartbeat < cutoff {
                // Remove related identity mappings
                if let Some(ext_id) = self.reverse_mappings.get(&actor.id) {
                    self.mappings.remove(ext_id);
                    self.reverse_mappings.remove(&actor.id);
                }
                false
            } else {
                true
            }
        });
        
        // Clean up expired identity mappings
        self.clean_expired_mappings();
    }

    fn clean_expired_mappings(&mut self) {
        let now = std::time::Instant::now();
        
        // Remove expired mappings
        let expired_ext_ids: Vec<String> = self
            .mappings
            .iter()
            .filter(|(_, mapping)| {
                mapping.expires_at.map_or(false, |exp| exp < now)
            })
            .map(|(ext_id, _)| ext_id.clone())
            .collect();
        
        for ext_id in expired_ext_ids {
            if let Some(mapping) = self.mappings.remove(&ext_id) {
                self.reverse_mappings.remove(&mapping.internal_actor_id);
            }
        }
    }

    pub fn get_mappings_by_type(&self, mapping_type: MappingType) -> Vec<IdentityMapping> {
        self.mappings
            .values()
            .filter(|m| m.mapping_type == mapping_type)
            .cloned()
            .collect()
    }

    pub fn get_all_active_actors(&self) -> Vec<ActorInstance> {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300);
        
        self.actor_registry
            .values()
            .filter(|actor| {
                actor.is_active && actor.last_heartbeat < cutoff
            })
            .cloned()
            .collect()
    }
}