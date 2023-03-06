use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

pub struct HandelNode<C> {
    public_seed: [u8; 32],
    num_levels: u32,
    num_nodes: u32,
    window_size: u32,
    /// Public id of this Handel node
    id: u32,
    /// `verification_priorities[l][j]` represents the Handel node id with `j'th` priority rank, at
    /// level `l`.
    verification_priorities: Vec<Vec<u32>>,
    individual_contribution: C,
    /// `contribution_prioritization_vector[l][j]` is the rank of `node_id` for the `j'th` node,
    /// for level `l`.
    contribution_prioritization_vector: Vec<Vec<u32>>,
    best_incoming_aggregate_contribution: Vec<Option<ScoredContribution<C>>>,
    best_outgoing_aggregate_contribution: Vec<Option<ScoredContribution<C>>>,
    /// `individual_verified_contributions[l]` denotes all verified individual contributions received by
    /// other nodes at level `l`.
    individual_verified_contributions: Vec<Vec<(u32, C)>>,
    unverified_contributions: Vec<Vec<UnverifiedContribution<C>>>,
    incoming_level_status: Vec<LevelStatus>,
    byzantine_nodes: Vec<u32>,
}

impl<C> HandelNode<C>
where
    C: Aggregable + Weighable + Verifiable + Clone,
{
    pub fn handle_incoming_contribution(&mut self, msg: HandelMsg<C>) {
        if self.incoming_level_status[msg.level as usize] == LevelStatus::Complete
            || self.byzantine_nodes.contains(&msg.sender_id)
        {
            return;
        }

        if let Some(pos) = self.unverified_contributions[msg.level as usize]
            .iter()
            .position(|UnverifiedContribution { sender_id, .. }| *sender_id == msg.sender_id)
        {
            self.unverified_contributions[msg.level as usize][pos] = UnverifiedContribution {
                sender_id: msg.sender_id,
                aggregate_contribution: msg.sender_aggregate_contribution,
                individual_contribution: msg.sender_individual_contribution,
            };
        } else {
            self.unverified_contributions[msg.level as usize].push(UnverifiedContribution {
                sender_id: msg.sender_id,
                aggregate_contribution: msg.sender_aggregate_contribution,
                individual_contribution: msg.sender_individual_contribution,
            });
        }

        self.try_verify(msg.level as usize);
    }

    pub fn try_verify(&mut self, level: usize) {
        let mut ranked_contributions = vec![];
        for &node_id in &self.verification_priorities[level] {
            if let Some(pos) = self.unverified_contributions[level]
                .iter()
                .position(|uc| uc.sender_id == node_id)
            {
                let uc = self.unverified_contributions[level].swap_remove(pos);
                ranked_contributions.push(uc);
            }
            if ranked_contributions.len() as u32 == self.window_size {
                break;
            }
        }

        // Now find the highest scored contribution
        if !ranked_contributions.is_empty() {
            let mut best_contribution = ranked_contributions.pop().unwrap();
            let mut best_score =
                self.score_incoming_contribution(&best_contribution.aggregate_contribution, level);
            for rc in ranked_contributions {
                let score = self.score_incoming_contribution(&rc.aggregate_contribution, level);
                if score > best_score {
                    best_score = score;
                    best_contribution = rc;
                }
            }

            // If both aggregate and individual contributions are verified
            if Verifiable::verify(&best_contribution.aggregate_contribution)
                && Verifiable::verify(&best_contribution.individual_contribution)
            {
                // Update best incoming aggregate contribution, if needed
                if let Some(ref b) = self.best_incoming_aggregate_contribution[level] {
                    if b.score < best_score {
                        self.best_incoming_aggregate_contribution[level] = Some(ScoredContribution {
                            score: best_score,
                            contribution: best_contribution.aggregate_contribution,
                        });
                    }
                } else {
                    self.best_incoming_aggregate_contribution[level] = Some(ScoredContribution {
                        score: best_score,
                        contribution: best_contribution.aggregate_contribution,
                    });
                }

                // Update incoming individual contribution,
                if let Some(pos) = self.individual_verified_contributions[level]
                    .iter()
                    .position(|&(node_id, _)| node_id == best_contribution.sender_id)
                {
                    self.individual_verified_contributions[level][pos] = (
                        best_contribution.sender_id,
                        best_contribution.individual_contribution,
                    );
                } else {
                    self.individual_verified_contributions[level].push((
                        best_contribution.sender_id,
                        best_contribution.individual_contribution,
                    ));
                }

                // Update incoming level status
                let LevelStatus::Incomplete(ref node_ids) = self.incoming_level_status[level] else {
                    unreachable!()
                };
                if !node_ids.contains(&best_contribution.sender_id) {
                    let mut new_node_ids = node_ids.clone();
                    new_node_ids.push(best_contribution.sender_id);
                    if (new_node_ids.len() as u32) < calc_num_nodes_in_level(self.num_nodes, level as u32) {
                        self.incoming_level_status[level] = LevelStatus::Incomplete(new_node_ids);
                    } else {
                        self.incoming_level_status[level] = LevelStatus::Complete;

                        // Have new outgoing aggregate contribution
                    }
                }
            } else {
                // Otherwise sender is flagged as Byzantine, prune contributions
                self.byzantine_nodes.push(best_contribution.sender_id);
                while let Some(pos) = self.individual_verified_contributions[level]
                    .iter()
                    .position(|&(node_id, _)| node_id == best_contribution.sender_id)
                {
                    self.individual_verified_contributions[level].swap_remove(pos);
                }
            }
        }
    }

    pub fn score_incoming_contribution(&self, aggregate_contribution: &C, level: usize) -> u32 {
        if let Some(ref c) = self.best_incoming_aggregate_contribution[level] {
            if let Some(agg) = Aggregable::aggregate(&c.contribution, aggregate_contribution) {
                return Weighable::weigh(&agg);
            } else if level > 0 {
                let mut acc_agg = None;
                for (_, c) in self.individual_verified_contributions[level].iter().cloned() {
                    if let Some(a) = acc_agg {
                        if let Some(aa) = Aggregable::aggregate(&a, &c) {
                            acc_agg = Some(aa.clone());
                        } else {
                            acc_agg = Some(c);
                        }
                    }
                }
            }
        }
        0
    }

    fn gen_outbound_contribution(&self, level: usize) -> Option<HandelMsg<C>> {
        self.best_outgoing_aggregate_contribution[level]
            .as_ref()
            .map(|out| HandelMsg {
                level: level as u32,
                sender_id: self.id,
                sender_individual_contribution: self.individual_contribution.clone(),
                sender_aggregate_contribution: out.contribution.clone(),
                contact_sender: true,
            })
    }
}

pub struct HandelMsg<C> {
    level: u32,
    sender_id: u32,
    sender_individual_contribution: C,
    sender_aggregate_contribution: C,
    /// If true, then receiver needs to contact sender
    contact_sender: bool,
}

struct UnverifiedContribution<C> {
    sender_id: u32,
    aggregate_contribution: C,
    individual_contribution: C,
}

struct ScoredContribution<C> {
    score: u32,
    contribution: C,
}

#[derive(PartialEq, Eq)]
enum LevelStatus {
    Complete,
    // The node ids who've contributed to the level
    Incomplete(Vec<u32>),
}

#[derive(Debug)]
struct VerificationPriorities {
    verification_priorities: Vec<Vec<u32>>,
    contribution_prioritization_vector: Vec<Vec<u32>>,
}

fn gen_verification_priorities(
    node_id: u32,
    public_seed: [u8; 32],
    mut num_nodes: u32,
    num_levels: u32,
) -> VerificationPriorities {
    let mut rng = StdRng::from_seed(public_seed);
    let mut vp = Vec::with_capacity(num_levels as usize);
    let mut cpv = Vec::with_capacity(num_levels as usize);
    for _ in 0..num_levels {
        let mut cpv_level = vec![];
        let mut v: Vec<u32> = (0..num_nodes).into_iter().collect();
        v.shuffle(&mut rng);
        for i in 0..num_nodes {
            let v_without_i: Vec<u32> = v
                .iter()
                .filter_map(|n| if *n != i { Some(*n) } else { None })
                .collect();
            if i != node_id {
                let rank = v_without_i.iter().position(|n_id| *n_id == node_id).unwrap();
                cpv_level.push(rank as u32);
            } else {
                vp.push(v_without_i);
            }
        }
        cpv.push(cpv_level);
        num_nodes /= 2;
    }
    VerificationPriorities {
        verification_priorities: vp,
        contribution_prioritization_vector: cpv,
    }
}

// Assuming `num_nodes_at_level_0` is power of 2
fn calc_num_nodes_in_level(num_nodes_at_level_0: u32, level: u32) -> u32 {
    if level == 0 {
        num_nodes_at_level_0
    } else {
        num_nodes_at_level_0 / (2 * level)
    }
}

pub trait Aggregable {
    fn aggregate(c_0: &Self, c_1: &Self) -> Option<Self>
    where
        Self: std::marker::Sized;
}

pub trait Verifiable {
    fn verify(c: &Self) -> bool;
}

pub trait Weighable: Aggregable {
    fn weigh(contribution: &Self) -> u32;
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;

    use super::{gen_verification_priorities, VerificationPriorities};

    #[test]
    fn test_verification_priorities() {
        let public_seed: [u8; 32] = repeat(2_u8).take(32).collect::<Vec<u8>>().try_into().unwrap();
        let node_id = 0;
        let VerificationPriorities {
            verification_priorities,
            contribution_prioritization_vector,
        } = gen_verification_priorities(node_id, public_seed, 8, 4);

        dbg!(verification_priorities);
        dbg!(contribution_prioritization_vector);
    }
}
