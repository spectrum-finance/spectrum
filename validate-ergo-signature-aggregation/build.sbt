import Dependencies._

conflictManager := ConflictManager.latestRevision
ThisBuild / scalaVersion := "2.13.11"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / organization := "com.example"
ThisBuild / organizationName := "example"

val circeVersion = "0.14.5"
val http4sVersion = "0.23.23"

lazy val root = (project in file("."))
  .settings(
    assembly / mainClass := Some("example.ContractTesting"),
    name := "validate-ergo-signature-aggregation",
    dependencyOverrides += "io.circe" %% "circe-core" % circeVersion,
    dependencyOverrides += "io.circe" %% "circe-generic" % circeVersion,
    dependencyOverrides += "io.circe" %% "circe-jawn" % circeVersion,
    libraryDependencies ++= Seq(
      "org.ergoplatform" %% "ergo-appkit" % "5.0.3",
      "org.scorexfoundation" %% "sigma-state" % "5.0.8",
      "ch.qos.logback" % "logback-classic" % "1.2.3",
      "org.http4s" %% "http4s-ember-client" % http4sVersion,
      "org.http4s" %% "http4s-ember-server" % http4sVersion,
      "org.http4s" %% "http4s-dsl" % http4sVersion,
      "org.http4s" %% "http4s-circe" % http4sVersion,
      "io.circe" %% "circe-generic" % circeVersion,
      // Optional for string interpolation to JSON model
      "io.circe" %% "circe-literal" % circeVersion
    )
  )

resolvers += Resolver.bintrayRepo("ergoplatform", "ergo")

// See https://www.scala-sbt.org/1.x/docs/Using-Sonatype.html for instructions on how to publish to Sonatype.
