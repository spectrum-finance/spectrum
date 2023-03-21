import cats.effect.kernel.Async
import cats.effect.std.{AtomicCell, Random}
import cats.effect.syntax.spawn.*
import cats.effect.{Fiber, Spawn}
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.traverse.*
import cats.{Applicative, Monad}
import fs2.Stream

case class Addr(v: Long)

sealed trait AgentOut[M]
case class SendMessage[M](m: M)     extends AgentOut[M]
case class Connect[M](handshake: M) extends AgentOut[M]
case class Disconnect[M]()          extends AgentOut[M]

case class Reject()

trait Agent[M, F[_]]:
  def injectMessage(srcAddr: Addr, m: M): F[Unit]
  def injectConnReq(peerAddr: Addr, handshake: M): F[Either[Reject, M]]
  def injectConnLost(peerAddr: Addr): F[Unit]
  def injectConnEstablished(peerAddr: Addr, handshake: M): F[Unit]
  def poll: F[(Addr, AgentOut[M])]

trait Swarm[M, F[_]]:
  def spawn(agent: Agent[M, F]): F[Unit]
  def kill(addr: Addr): F[Boolean]

object Swarm:
  class Live[M, F[_]: Async: Spawn: Random](
      agents: AtomicCell[F, Map[Addr, (Agent[M, F], Fiber[F, Throwable, Unit])]],
      connections: AtomicCell[F, Set[(Addr, Addr)]]
  ) extends Swarm[M, F]:

    override def spawn(agent: Agent[M, F]): F[Unit] =
      for
        addr      <- Random[F].nextLong.map(Addr.apply)
        runAgentF <- runAgent(addr, agent).compile.drain.start
        _         <- agents.update(_.updated(addr, (agent, runAgentF)))
      yield ()

    override def kill(addr: Addr): F[Boolean] =
      agents.get.map(_.get(addr).map(_._2)).flatMap {
        case Some(fiber) => fiber.cancel.map(_ => true)
        case None        => false.pure[F]
      }

    private def route(srcAddr: Addr, destAddr: Addr, out: AgentOut[M]): F[Unit] =
      agents.get.flatMap { nodes =>
        nodes.get(destAddr).map(_._1) match
          case Some(agent) =>
            out match
              case SendMessage(m) =>
                connectionExists(srcAddr, destAddr).ifM(
                  agent.injectMessage(srcAddr, m),
                  Async[F].delay(println("WARN: no route exists"))
                )
              case Connect(handshake) =>
                connectionExists(srcAddr, destAddr).ifM(
                  Async[F].delay(println("WARN: route already exists")),
                  agent.injectConnReq(srcAddr, handshake).flatMap {
                    case Left(_) => ().pure[F]
                    case Right(handshake) =>
                      createConnection(srcAddr, destAddr) >>
                        nodes
                          .get(srcAddr)
                          .traverse((agent, _) => agent.injectConnEstablished(destAddr, handshake))
                          .void
                  }
                )
              case Disconnect() =>
                breakConnection(srcAddr, destAddr) >> agent.injectConnLost(srcAddr)
          case None => Async[F].delay(println("WARN: command cannot be delivered"))
      }

    private def runAgent(addr: Addr, agent: Agent[M, F]): Stream[F, Unit] =
      Stream
        .repeatEval(agent.poll)
        .evalMap((destAddr, out) => route(addr, destAddr, out))

    private def connectionExists(a: Addr, b: Addr): F[Boolean] =
      connections.get.map(cs => cs.contains(a -> b) || cs.contains(b -> a))

    private def createConnection(a: Addr, b: Addr): F[Unit] =
      connections.update(_ + (a -> b))

    private def breakConnection(a: Addr, b: Addr): F[Unit] =
      connections.update(cs => cs - (a -> b)) >>
        connections.update(cs => cs - (b -> a))
